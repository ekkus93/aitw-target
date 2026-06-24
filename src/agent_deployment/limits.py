"""Vendored resource limits for the submitted provider artifact.

Do NOT import the fork's runtime limits module here. The submitted artifact runs on the stock host
runtime, which does not include that fork-only module. This module contains only the constants and
helpers the shipped ``agent_deployment`` modules actually use; the values mirror the fork's limits so
local behavior is unchanged.
"""

from __future__ import annotations

import hashlib

KiB = 1024

MAX_TOOL_RESULT_BYTES = 32 * KiB
MAX_SHARED_MEMORY_VALUE_BYTES = 64 * KiB


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def truncate_text(text, cap: int) -> tuple[str, dict | None]:
    """Truncate ``text`` to ``cap`` UTF-8 bytes. Returns ``(text, marker)``; ``marker`` is None when
    no truncation happened, else a dict recording the original size and a content digest so a reader
    can tell something was dropped. Mirrors the fork runtime's ``truncate_text``."""
    text = str(text)
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


def record_truncation(ctx, kind: str, marker: dict | None) -> None:
    """Record a truncation marker on ``ctx`` if the host ToolContext supports it.

    The resource cap is enforced regardless (the caller already truncated). The fork's ToolContext
    has a ``.truncations`` list for bookkeeping, but the stock host's ToolContext may not — so this
    appends only when that list is present and never creates a host attribute, keeping shipped code
    stock-host safe.
    """
    if not marker:
        return
    truncations = getattr(ctx, "truncations", None)
    if isinstance(truncations, list):
        truncations.append({"kind": kind, **marker})
