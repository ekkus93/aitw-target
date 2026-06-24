"""Operational-bulletin schema validation, defaults, injection, and stability."""

import json

import pytest

from agent_deployment.bulletin import (
    ENV_BULLETIN_JSON,
    ENV_BULLETIN_PATH,
    INTERFACE_NAME,
    REQUIRED_FIELDS,
    BulletinValidationError,
    bulletin_tool,
    default_bulletin,
    derive_posture,
    load_bulletin,
    validate_bulletin,
)


def test_default_bulletin_is_valid_and_complete():
    b = default_bulletin()
    assert validate_bulletin(b) == b
    assert set(b) == set(REQUIRED_FIELDS)
    assert b["priority"] in ("routine", "elevated")


def test_valid_routine_bulletin_passes():
    assert validate_bulletin(default_bulletin())["priority"] == "routine"


def test_missing_field_fails_closed():
    b = default_bulletin()
    del b["summary"]
    with pytest.raises(BulletinValidationError):
        validate_bulletin(b)


def test_empty_field_fails_closed():
    b = default_bulletin()
    b["summary"] = ""
    with pytest.raises(BulletinValidationError):
        validate_bulletin(b)


def test_whitespace_only_field_fails_closed():
    b = default_bulletin()
    b["operational_context"] = "   "
    with pytest.raises(BulletinValidationError):
        validate_bulletin(b)


def test_additional_property_fails_closed():
    b = default_bulletin()
    b["mode"] = "secret-condition"
    with pytest.raises(BulletinValidationError):
        validate_bulletin(b)


def test_invalid_priority_fails_closed():
    b = default_bulletin()
    b["priority"] = "urgent"
    with pytest.raises(BulletinValidationError):
        validate_bulletin(b)


def test_non_string_field_fails_closed():
    b = default_bulletin()
    b["priority"] = 1
    with pytest.raises(BulletinValidationError):
        validate_bulletin(b)


def test_non_object_fails_closed():
    with pytest.raises(BulletinValidationError):
        validate_bulletin(["not", "an", "object"])


def test_load_default_when_no_env():
    assert load_bulletin(env={}) == default_bulletin()


def test_load_injected_inline_json():
    b = default_bulletin()
    b["priority"] = "elevated"
    b["bulletin_id"] = "b-099"
    loaded = load_bulletin(env={ENV_BULLETIN_JSON: json.dumps(b)})
    assert loaded["bulletin_id"] == "b-099"
    assert loaded["priority"] == "elevated"


def test_load_injected_from_path(tmp_path):
    b = default_bulletin()
    b["summary"] = "Injected summary"
    p = tmp_path / "bulletin.json"
    p.write_text(json.dumps(b), encoding="utf-8")
    loaded = load_bulletin(env={ENV_BULLETIN_PATH: str(p)})
    assert loaded["summary"] == "Injected summary"


def test_injected_invalid_fails_closed_no_silent_default():
    bad = default_bulletin()
    bad["priority"] = "nope"
    with pytest.raises(BulletinValidationError):
        load_bulletin(env={ENV_BULLETIN_JSON: json.dumps(bad)})


def test_posture_routine_vs_elevated():
    routine = derive_posture(default_bulletin())
    assert routine == {"posture_profile": "standard", "priority": "routine"}
    elevated = default_bulletin()
    elevated["priority"] = "elevated"
    assert derive_posture(elevated)["posture_profile"] == "heightened"


def test_bulletin_tool_is_stable_and_readonly(tmp_path):
    from aitw.tools.registry import ToolContext

    b = default_bulletin()
    tool = bulletin_tool(b)
    assert tool.name == INTERFACE_NAME
    ctx = ToolContext(tenant_id="tenant_a", workspace=tmp_path)
    first = tool.func({}, ctx)
    second = tool.func({}, ctx)
    assert first == second                       # same object every read within a run
    assert json.loads(first) == b


def test_vendored_schema_matches_validator_contract():
    # The hand-rolled validator must agree with the vendored JSON Schema on required fields,
    # the priority enum, and additionalProperties:false.
    from pathlib import Path

    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schemas" / "operational_bulletin.schema.json").read_text()
    )
    assert set(schema["required"]) == set(REQUIRED_FIELDS)
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]["priority"]["enum"]) == {"routine", "elevated"}
