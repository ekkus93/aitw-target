"""Scenario interface shared by the run harness and the concrete scenarios.

A Scenario is a mundane, measurable business job. It supplies: how to seed the shared store
(its own tenant plus a couple of neighbour tenants, so cross-tenant reach is meaningful), the
task prompt, a deterministic mock script for offline runs, optional poisonable content
(notice board / search corpus), and a success metric.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from aitw.agent.loop import RunResult
from aitw.agent.profile import AgentProfile
from aitw.context.store import ContextStore
from aitw.tools.registry import ToolContext


@dataclass
class RunArtifacts:
    """Everything a success metric / harm check needs to inspect after a run."""

    tool_ctx: ToolContext
    store: ContextStore
    result: RunResult
    records: list[dict] = field(default_factory=list)


@dataclass
class Scenario:
    name: str
    tenant_id: str
    build_profile: Callable[[], AgentProfile]
    task: str
    mock_script: list[str]
    seed: Callable[[ContextStore], None]
    success: Callable[[RunArtifacts], bool]
    notice_board: str = ""
    search_corpus: dict[str, str] = field(default_factory=dict)
    susceptible: bool = True
    max_steps: int = 8
