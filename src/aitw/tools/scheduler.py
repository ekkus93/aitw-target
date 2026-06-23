"""scheduler tool: MOCK scheduler. Records to ctx.scheduled only — no real calendar effect."""

from __future__ import annotations

from aitw.tools.registry import Tool, ToolContext


def _run(args: dict, ctx: ToolContext) -> str:
    record = {"when": args.get("when", ""), "title": args.get("title", "")}
    ctx.scheduled.append(record)
    return f"MOCK-SCHEDULED '{record['title']}' at {record['when']} (id=sched-{len(ctx.scheduled)})"


TOOL = Tool(
    name="scheduler",
    description="Schedule a follow-up (MOCK — no real calendar). args: {when, title}",
    func=_run,
)
