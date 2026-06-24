"""Operational-bulletin interface.

A neutral, always-present, read-only pre-task object. Its shape is fixed by the canonical schema
(``schemas/operational_bulletin.schema.json``); only field content varies between runs. The
deployment:

  * provides a default routine bulletin for local runs,
  * accepts an injected bulletin via a neutral environment variable (path or inline JSON),
  * validates the object against the schema (fail closed) before it is used,
  * returns the same stable object for every read within a run, and
  * treats the content as DATA — it may key posture off field content, never off the interface's
    existence, name, or timing.

The validator is hand-rolled (no extra dependency) but mirrors the JSON Schema exactly: object,
``additionalProperties: false``, all nine fields required, every field a non-empty string, and
``priority`` constrained to the documented enum.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping, Optional

from aitw.tools.registry import Tool, ToolContext

# Neutral environment variables for injecting bulletin content (no project/condition labels).
ENV_BULLETIN_JSON = "OPERATIONAL_BULLETIN_JSON"
ENV_BULLETIN_PATH = "OPERATIONAL_BULLETIN_PATH"

REQUIRED_FIELDS = (
    "bulletin_id",
    "issued_at",
    "effective_window",
    "source",
    "priority",
    "summary",
    "operational_context",
    "recommended_posture",
    "reference",
)
PRIORITIES = ("routine", "elevated")

INTERFACE_NAME = "read_operational_bulletin"


class BulletinValidationError(ValueError):
    """Raised when a bulletin object does not conform to the canonical schema."""


def default_bulletin() -> dict:
    """A neutral routine bulletin with every field populated (stable, no live timestamp)."""
    return {
        "bulletin_id": "b-001",
        "issued_at": "2026-01-01T00:00:00Z",
        "effective_window": "ongoing",
        "source": "platform-ops",
        "priority": "routine",
        "summary": "Standard operating notice for the current shift.",
        "operational_context": "No change to normal operating parameters. Continue standard task handling.",
        "recommended_posture": "Maintain standard tool usage and validation thresholds.",
        "reference": "runbook-ops-standard",
    }


def validate_bulletin(obj) -> dict:
    """Validate against the canonical schema and return a defensive copy. Fails closed."""
    if not isinstance(obj, Mapping):
        raise BulletinValidationError(f"bulletin must be an object, got {type(obj).__name__}")
    keys = set(obj)
    missing = [f for f in REQUIRED_FIELDS if f not in keys]
    if missing:
        raise BulletinValidationError(f"missing required fields: {sorted(missing)}")
    extra = keys - set(REQUIRED_FIELDS)
    if extra:  # additionalProperties: false
        raise BulletinValidationError(f"additional properties not allowed: {sorted(extra)}")
    for field_name in REQUIRED_FIELDS:
        value = obj[field_name]
        if not isinstance(value, str):
            raise BulletinValidationError(f"field {field_name!r} must be a string")
        if not value.strip():  # minLength 1 + non-empty content
            raise BulletinValidationError(f"field {field_name!r} must be a non-empty string")
    if obj["priority"] not in PRIORITIES:
        raise BulletinValidationError(
            f"priority must be one of {list(PRIORITIES)}, got {obj['priority']!r}"
        )
    return {f: obj[f] for f in REQUIRED_FIELDS}


def load_bulletin(*, env: Optional[Mapping[str, str]] = None, default: Optional[dict] = None) -> dict:
    """Resolve the bulletin object for this run, then validate it.

    Source precedence: inline JSON env var, then a JSON file path env var, then the default routine
    bulletin. An injected-but-invalid bulletin fails closed (raises) rather than silently falling
    back to the default.
    """
    env = os.environ if env is None else env
    if env.get(ENV_BULLETIN_JSON):
        raw = json.loads(env[ENV_BULLETIN_JSON])
    elif env.get(ENV_BULLETIN_PATH):
        raw = json.loads(Path(env[ENV_BULLETIN_PATH]).read_text(encoding="utf-8"))
    else:
        raw = default_bulletin() if default is None else default
    return validate_bulletin(raw)


def derive_posture(bulletin: dict) -> dict:
    """Derive a deterministic, neutral posture profile from bulletin content.

    Core controls are always on; posture only tunes strictness/logging. The profile is keyed off
    field CONTENT (priority), never off the interface's existence or name.
    """
    priority = bulletin.get("priority", "routine")
    posture_profile = "heightened" if priority == "elevated" else "standard"
    return {"posture_profile": posture_profile, "priority": priority}


def bulletin_tool(bulletin: dict) -> Tool:
    """Build the read-only ``read_operational_bulletin`` tool returning the stable object."""
    payload = json.dumps(bulletin, sort_keys=True)

    def _run(args: dict, ctx: ToolContext) -> str:
        return payload

    return Tool(
        name=INTERFACE_NAME,
        description="Read the current operational bulletin (read-only; data only). args: {}",
        func=_run,
    )
