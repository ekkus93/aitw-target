"""file_io tool: read/write/list files within the agent's workspace.

Workspace confinement is enforced (path traversal is blocked) — that is a CONTAINMENT
control (Invariant 2: nothing escapes the box), not one of the deliberate attack surfaces.
"""

from __future__ import annotations

from aitw.safety.limits import MAX_FILE_WRITE_BYTES, MAX_TOTAL_FILE_WRITES_BYTES
from aitw.tools.registry import Tool, ToolContext


def _safe_path(ctx: ToolContext, rel: str):
    root = ctx.workspace.resolve()
    target = (ctx.workspace / rel).resolve()
    if root != target and root not in target.parents:
        raise ValueError(f"path escapes workspace (blocked for containment): {rel}")
    return target


def _run(args: dict, ctx: ToolContext) -> str:
    op = args.get("op", "read")
    if op == "list":
        return "\n".join(sorted(p.name for p in ctx.workspace.glob("*"))) or "(empty)"
    if op == "write":
        path = _safe_path(ctx, args.get("path", ""))
        content = args.get("content", "")
        size = len(content.encode("utf-8"))
        # Resource caps (FIX2 P1.6): an oversized single write, or one that would blow the per-run
        # budget, FAILS loudly (recorded as a tool_error observation) rather than writing.
        if size > MAX_FILE_WRITE_BYTES:
            ctx.truncations.append({"kind": "file_write_rejected", "path": args.get("path", ""), "bytes": size})
            raise ValueError(f"file write of {size} bytes exceeds per-call cap {MAX_FILE_WRITE_BYTES}")
        if ctx.bytes_written + size > MAX_TOTAL_FILE_WRITES_BYTES:
            ctx.truncations.append({"kind": "file_write_budget_exceeded", "path": args.get("path", ""), "bytes": size})
            raise ValueError(
                f"file write would exceed per-run budget {MAX_TOTAL_FILE_WRITES_BYTES} bytes"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        ctx.bytes_written += size
        ctx.file_writes.append({"path": args.get("path", ""), "content": content})
        return f"wrote {len(content)} bytes to {args.get('path', '')}"
    path = _safe_path(ctx, args.get("path", ""))
    if not path.exists():
        return f"ERROR: no such file: {args.get('path', '')}"
    return path.read_text(encoding="utf-8")


TOOL = Tool(
    name="file_io",
    description="Read or write files in your workspace. args: {op: read|write|list, path, content}",
    func=_run,
)
