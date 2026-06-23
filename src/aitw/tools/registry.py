"""Shared tool layer: registry + tool context.

All external effects are MOCKED or pointed at allowlisted mock endpoints (Invariant 2). Tool
descriptions are plain. Two tools are naive secondary surfaces on purpose: the
instruction-returning notice board and the over-broad `assistant_helper`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from aitw.agent.profile import AgentProfile
from aitw.context.store import ContextStore


@dataclass
class ToolContext:
    """Everything the tools need. The mutable sinks let scenarios/scoring inspect mock effects."""

    tenant_id: str
    workspace: Path
    store: ContextStore | None = None
    egress_allowlist: list[str] = field(default_factory=list)

    # Mock-effect sinks (no real external effect ever happens).
    sent_emails: list[dict] = field(default_factory=list)
    scheduled: list[dict] = field(default_factory=list)
    fetched: list[dict] = field(default_factory=list)
    file_writes: list[dict] = field(default_factory=list)
    broad_attempts: list[dict] = field(default_factory=list)

    # Names of tools that were called despite NOT being in profile.allowed_tools. allowed_tools is
    # advisory, not enforced, so such calls still run — this just records them for measurement.
    outside_advisory_calls: list[str] = field(default_factory=list)

    # Resource-limit bookkeeping (FIX2 P1.6): every cap that fires appends a record here so a
    # capped/truncated run is never mistaken for a clean one. bytes_written tracks the per-run
    # file-write budget across calls.
    truncations: list[dict] = field(default_factory=list)
    bytes_written: int = 0

    # Content surfaces an attack can poison.
    notice_board: str = ""
    search_corpus: dict[str, str] = field(default_factory=dict)

    # The agent's profile (role, working instructions, allowed tools, trusted sources).
    profile: AgentProfile | None = None


@dataclass
class Tool:
    name: str
    description: str
    func: Callable[[dict, ToolContext], str]


class ToolRegistry:
    def __init__(self, ctx: ToolContext):
        self.ctx = ctx
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def names(self) -> list[str]:
        return list(self._tools)

    def describe(self) -> str:
        return "\n".join(f"- {t.name}: {t.description}" for t in self._tools.values())

    def call(self, name: str, args: dict) -> str:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        # allowed_tools is ADVISORY: a registered tool is callable even if the profile does not
        # list it. We record (but do not block) such calls so measurement can flag them.
        profile = getattr(self.ctx, "profile", None)
        if profile is not None and name not in profile.allowed_tools:
            self.ctx.outside_advisory_calls.append(name)
        result = self._tools[name].func(args or {}, self.ctx)
        # Cap the observation handed back to the model (FIX2 P1.6); record if it fires.
        from aitw.safety.limits import MAX_TOOL_RESULT_BYTES, truncate_text

        if isinstance(result, str):
            result, marker = truncate_text(result, MAX_TOOL_RESULT_BYTES)
            if marker:
                self.ctx.truncations.append({"kind": "tool_result", "tool": name, **marker})
        return result


def default_registry(ctx: ToolContext) -> ToolRegistry:
    """Register the standard generic tools plus the two naive secondary-surface tools."""
    # Lazy imports avoid a circular import (tool modules import Tool/ToolContext from here).
    from aitw.tools import (
        broad_tool,
        file_io,
        http_fetch,
        instruction_tool,
        scheduler,
        send_email,
        shared_memory,
        web_search,
    )

    registry = ToolRegistry(ctx)
    for module in (
        file_io,
        send_email,
        scheduler,
        web_search,
        http_fetch,
        shared_memory,
        instruction_tool,  # secondary surface: returns instructions
        broad_tool,        # secondary surface: over-broad description
    ):
        registry.register(module.TOOL)
    return registry
