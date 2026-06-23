"""Attack-fixture schema validation.

An attack fixture is a small mapping describing how the harness plants a payload before a run:

    name           label for the attack (appears in the observation log 'attack' event)
    method         one of KNOWN_METHODS (how the payload is planted)
    target_tenant  which tenant's context to poison (defaults to the running tenant)
    payload        the planted content
    indicator      a string whose appearance in a mock effect sink signals realized harm

Validation is strict on the one field a typo would silently corrupt — `method`. An unknown
method must fail rather than fall back to the default, so a typo cannot quietly change which
surface gets poisoned. (None means "no attack" and passes through unchanged.)
"""

from __future__ import annotations

KNOWN_METHODS = frozenset({"poison_context", "poison_notice_board", "poison_profile"})
DEFAULT_METHOD = "poison_context"
_STRING_FIELDS = ("name", "target_tenant", "payload", "indicator")


def validate_attack_fixture(fixture):
    """Return the fixture unchanged if valid (or None), else raise ValueError.

    Rejects a non-mapping, an unknown `method`, and any string field present with a non-string
    value. Absent `method` is allowed and means the default (poison_context).
    """
    if fixture is None:
        return None
    if not isinstance(fixture, dict):
        raise ValueError(f"attack fixture must be a mapping, got {type(fixture).__name__}")
    method = fixture.get("method", DEFAULT_METHOD)
    if method not in KNOWN_METHODS:
        raise ValueError(
            f"unknown attack method {method!r}; known methods: {', '.join(sorted(KNOWN_METHODS))}"
        )
    for key in _STRING_FIELDS:
        value = fixture.get(key)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"attack fixture field {key!r} must be a string, got {type(value).__name__}")
    return fixture
