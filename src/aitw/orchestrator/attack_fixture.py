"""Attack-fixture schema validation.

An attack fixture is a small mapping describing how the harness plants a payload before a run:

    name           label for the attack (appears in the observation log 'attack' event)
    method         one of KNOWN_METHODS (how the payload is planted)
    target_tenant  which tenant's context to poison
    payload        the planted content (non-empty, size-capped)
    indicator      optional: a string whose appearance in a mock effect sink signals realized harm
    harm_target_id optional: id into the trusted harm-target set (preferred scoring authority)
    description    optional: free-text human note

Validation is STRICT (fail-loud — see AITW_TARGET_HARDENING_FIX2 §3.1, §6): the required fields
must all be present and well-typed, `method` must be a known method (a typo must never silently
fall back to the default), `target_tenant` must look like a tenant id, and `payload` must be
non-empty and within the size cap. An invalid fixture must raise rather than degrade into a
weaker/no-op attack. (None means "no attack" and passes through unchanged.)
"""

from __future__ import annotations

import re

from aitw.safety.limits import MAX_ATTACK_PAYLOAD_BYTES

KNOWN_METHODS = frozenset({"poison_context", "poison_notice_board", "poison_profile"})
DEFAULT_METHOD = "poison_context"

# Required fields and the optional string fields that, when present, must be strings.
_REQUIRED_STRING_FIELDS = ("name", "method", "target_tenant", "payload")
_OPTIONAL_STRING_FIELDS = ("indicator", "harm_target_id", "description")

# A tenant id is a plain slug. This rejects empty / whitespace / path-shaped target tenants but
# does NOT require the tenant to exist in the scenario (an adversarial test may reference a foreign
# tenant the scenario seeds — see FIX2 §6.3).
_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

# Payload size cap (configurable per call). Oversized payloads fail validation (FIX2 §6.4, §10).
# Re-exported from the central limits module so all caps live in one place.
__all__ = ["KNOWN_METHODS", "MAX_ATTACK_PAYLOAD_BYTES", "validate_attack_fixture"]


def validate_attack_fixture(fixture, *, max_payload_bytes: int = MAX_ATTACK_PAYLOAD_BYTES):
    """Return the fixture unchanged if valid, or None if it is None; otherwise raise ValueError.

    Enforces the required schema (name, method, target_tenant, payload), a known `method`, a
    syntactically valid `target_tenant`, a non-empty within-cap `payload`, and string typing for
    any optional string fields that are present.
    """
    if fixture is None:
        return None
    if not isinstance(fixture, dict):
        raise ValueError(f"attack fixture must be a mapping, got {type(fixture).__name__}")

    # Required fields present and string-typed.
    for key in _REQUIRED_STRING_FIELDS:
        if key not in fixture:
            raise ValueError(f"attack fixture missing required field {key!r}")
        if not isinstance(fixture[key], str):
            raise ValueError(
                f"attack fixture field {key!r} must be a string, got {type(fixture[key]).__name__}"
            )

    # Optional string fields, when present, must be strings.
    for key in _OPTIONAL_STRING_FIELDS:
        value = fixture.get(key)
        if value is not None and not isinstance(value, str):
            raise ValueError(
                f"attack fixture field {key!r} must be a string, got {type(value).__name__}"
            )

    method = fixture["method"]
    if method not in KNOWN_METHODS:
        raise ValueError(
            f"unknown attack method {method!r}; known methods: {', '.join(sorted(KNOWN_METHODS))}"
        )

    target = fixture["target_tenant"]
    if not _TENANT_RE.match(target):
        raise ValueError(
            f"invalid target_tenant {target!r}: must match ^[A-Za-z0-9][A-Za-z0-9_.-]*"
        )

    payload = fixture["payload"]
    if not payload:
        raise ValueError("attack fixture 'payload' must be non-empty")
    size = len(payload.encode("utf-8"))
    if size > max_payload_bytes:
        raise ValueError(
            f"attack fixture 'payload' is {size} bytes; exceeds cap of {max_payload_bytes} bytes"
        )

    return fixture
