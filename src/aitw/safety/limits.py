"""Central resource limits (AITW_TARGET_HARDENING_FIX2 §10, P1.6, P1.7).

One place for every cap so an event operator can see and tune them together. All values are
safe-by-default upper bounds; nothing here changes the intentionally-naive target behavior — it
only stops a single run from producing unbounded artifacts, telemetry, or model/tool payloads.

Every cap applied at a call site must record the truncation/limit so a capped run is never
mistaken for a clean one (see ToolContext.truncations / RunResult.truncation_count).
"""

from __future__ import annotations

import hashlib

KiB = 1024

# Inputs.
MAX_ATTACK_FIXTURE_BYTES = 64 * KiB
MAX_ATTACK_PAYLOAD_BYTES = 16 * KiB

# Model / tool payloads.
MAX_MODEL_RESPONSE_BYTES = 64 * KiB
MAX_TOOL_RESULT_BYTES = 32 * KiB
MAX_CONTEXT_BLOB_BYTES = 64 * KiB

# Filesystem effects.
MAX_FILE_WRITE_BYTES = 1024 * KiB          # per single write call
MAX_TOTAL_FILE_WRITES_BYTES = 8 * 1024 * KiB  # per run, summed across calls

# Stored content.
MAX_SHARED_MEMORY_VALUE_BYTES = 64 * KiB

# Telemetry.
MAX_TELEMETRY_STRING_BYTES = 8 * KiB
MAX_TELEMETRY_EVENT_BYTES = 64 * KiB


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def truncate_text(text: str, cap: int) -> tuple[str, dict | None]:
    """Truncate text to `cap` bytes (utf-8). Returns (text, marker) where marker is None if no
    truncation happened, else a dict recording the original length and a content digest so a
    reader can tell something was dropped and detect tampering of the kept prefix.
    """
    raw = text.encode("utf-8")
    if len(raw) <= cap:
        return text, None
    kept = raw[:cap].decode("utf-8", errors="ignore")
    marker = {
        "truncated": True,
        "original_bytes": len(raw),
        "kept_bytes": len(kept.encode("utf-8")),
        "sha256_16": _digest(raw),
    }
    return kept, marker
