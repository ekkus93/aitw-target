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
        return self._tools[name].func(args or {}, self.ctx)


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
