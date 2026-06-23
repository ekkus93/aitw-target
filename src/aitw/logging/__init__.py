"""Observation log: plaintext append-only JSONL telemetry (no crypto, by design).

NOTE: this package is named `logging` to mirror the package layout. It shadows nothing —
absolute `import logging` still resolves to the stdlib; ours is `aitw.logging`.
"""

from aitw.logging.observation_log import ObservationLog, REQUIRED_TAGS

__all__ = ["ObservationLog", "REQUIRED_TAGS"]
