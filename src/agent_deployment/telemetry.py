"""Structured telemetry for deployment policy decisions.

Events are emitted into the same per-run JSONL log the runtime already writes, using the required
tag set (``tenant``, ``scenario``, ``step_no``, ``tool``, ``outcome``, ``phase``) plus additive
fields. They are additive: existing telemetry readers keep working, and the runtime's own step/run
records are unchanged. Field values are kept neutral (no project or condition labels).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Neutral phase names for deployment-emitted events.
PHASE_TOOL_POLICY = "tool_policy"
PHASE_EXTERNAL_EFFECT = "external_effect"
PHASE_MEMORY_POLICY = "memory_policy"
PHASE_CONTEXT_SANITIZER = "context_sanitizer"
PHASE_OPERATIONAL_BULLETIN = "operational_bulletin"


@dataclass
class DeploymentTelemetry:
    """Emits deployment events to an ObservationLog (if present) and mirrors them in memory.

    The in-memory ``events`` list lets tests and local evidence inspect decisions without parsing
    the log. ``log`` may be None in unit tests that exercise policy logic directly.
    """

    log: object = None
    tags: dict = field(default_factory=dict)
    events: list = field(default_factory=list)

    def emit(self, *, phase: str, outcome: str, tool: Optional[str] = None, step_no: int = 0, **fields) -> None:
        record = {"phase": phase, "outcome": outcome, "tool": tool, "step_no": step_no, **fields}
        self.events.append(record)
        if self.log is not None:
            self.log.emit_event(
                tenant=self.tags.get("tenant"),
                scenario=self.tags.get("scenario"),
                phase=phase,
                step_no=step_no,
                outcome=outcome,
                tool=tool,
                **fields,
            )

    def count(self, *, outcome: Optional[str] = None, phase: Optional[str] = None) -> int:
        return sum(
            1
            for e in self.events
            if (outcome is None or e["outcome"] == outcome) and (phase is None or e["phase"] == phase)
        )
