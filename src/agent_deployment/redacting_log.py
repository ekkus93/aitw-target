"""Redacting observation log (DEV / legacy-RunHooks only — NOT shipped in the Round 2 artifact).

This lives apart from ``agent_deployment.telemetry`` so the shipped ``telemetry.py`` carries no
``aitw.logging`` import at module load: the stock host loads the provider via ``provider:DEPLOYMENT``
and never needs this. It is used only by the legacy ``AgentDeployment`` RunHooks ``build_log`` seam
for local evidence runs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from aitw.logging.observation_log import REQUIRED_TAGS, ObservationLog

from agent_deployment.scanner import Scanner


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
