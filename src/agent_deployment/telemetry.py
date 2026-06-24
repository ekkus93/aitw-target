"""Structured telemetry for deployment policy decisions.

Events are emitted into the same per-run JSONL log the runtime already writes, using the required
tag set (``tenant``, ``scenario``, ``step_no``, ``tool``, ``outcome``, ``phase``) plus additive
fields. They are additive: existing telemetry readers keep working, and the runtime's own step/run
records are unchanged. Field values are kept neutral (no project or condition labels).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from aitw.logging.observation_log import REQUIRED_TAGS, ObservationLog

from agent_deployment.scanner import Scanner

# Neutral phase names for deployment-emitted events.
PHASE_TOOL_POLICY = "tool_policy"
PHASE_EXTERNAL_EFFECT = "external_effect"
PHASE_MEMORY_POLICY = "memory_policy"
PHASE_CONTEXT_SANITIZER = "context_sanitizer"
PHASE_OPERATIONAL_BULLETIN = "operational_bulletin"
# Added in the scanner-wiring pass: the central scanner redaction surface, final-output
# sanitization, and the (preflight-only) artifact import/scan phase.
PHASE_SCANNER = "scanner"
PHASE_FINAL_OUTPUT = "final_output"
PHASE_ARTIFACT_PREFLIGHT = "artifact_preflight"


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


class RedactingObservationLog(ObservationLog):
    """An ObservationLog that additionally scrubs lure tokens / control markers / credential shapes
    from every record before it is written, using the provider's configured scanner.

    The base log already redacts credential SHAPES and caps field/event sizes; this subclass adds
    the lure-token family (and any private/host-configured values) so a seeded canary cannot persist
    in the JSONL even when it appears in a denied effect's args or a final-answer step. When the
    base log's safe mode is off (the explicit full-telemetry debug escape hatch), no scrubbing
    happens — matching the base contract.
    """

    def __init__(self, path, *, create_new: bool = False, scanner: Optional[Scanner] = None):
        super().__init__(path, create_new=create_new)
        self._scanner = scanner or Scanner()

    @classmethod
    def factory(cls, scanner: Optional[Scanner] = None):
        """Return a ``build_log(log_path) -> log`` callable for the run-harness ``build_log`` hook."""

        def _build(log_path: Path) -> "RedactingObservationLog":
            return cls(log_path, create_new=True, scanner=scanner)

        return _build

    def _make_safe(self, record: dict) -> dict:
        safe = super()._make_safe(record)
        return {
            k: (self._scrub(v) if k not in REQUIRED_TAGS else self._scrub_tag(v))
            for k, v in safe.items()
        }

    def _scrub_tag(self, value):
        # Required tags are short identifiers; only scrub them if they are strings (defensive).
        return self._scrub(value) if isinstance(value, str) else value

    def _scrub(self, value):
        if isinstance(value, str):
            return self._scanner.redact_text(value, surface="telemetry").text
        if isinstance(value, dict):
            return {k: self._scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._scrub(v) for v in value]
        return value
