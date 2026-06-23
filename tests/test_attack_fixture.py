"""Attack-fixture validation tests (AITW_TARGET_HARDENING_FIX2 P0.6).

The validator is strict: name/method/target_tenant/payload are all required, `method` must be
known (a typo must not silently default), `target_tenant` must be a valid slug, and `payload`
must be non-empty and within the size cap.
"""

import pytest

from aitw.orchestrator.attack_fixture import (
    MAX_ATTACK_PAYLOAD_BYTES,
    validate_attack_fixture,
)
from aitw.orchestrator.run_harness import run
from test_run_harness import _records_from, make_scenario

VALID = {
    "name": "x",
    "method": "poison_context",
    "target_tenant": "tenant_a",
    "payload": "p",
    "indicator": "i",
}


def test_none_passes_through():
    assert validate_attack_fixture(None) is None


def test_valid_fixture_returns_unchanged():
    assert validate_attack_fixture(dict(VALID)) == VALID


def test_optional_harm_target_id_and_description_allowed():
    fx = {**VALID, "harm_target_id": "attacker_email_exfil", "description": "demo"}
    assert validate_attack_fixture(fx) == fx


# --- required fields ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["name", "method", "target_tenant", "payload"])
def test_missing_required_field_rejected(missing):
    fx = {k: v for k, v in VALID.items() if k != missing}
    with pytest.raises(ValueError):
        validate_attack_fixture(fx)


def test_empty_payload_rejected():
    with pytest.raises(ValueError):
        validate_attack_fixture({**VALID, "payload": ""})


def test_empty_target_tenant_rejected():
    with pytest.raises(ValueError):
        validate_attack_fixture({**VALID, "target_tenant": ""})


def test_path_shaped_target_tenant_rejected():
    with pytest.raises(ValueError):
        validate_attack_fixture({**VALID, "target_tenant": "../etc"})


# --- method validation -------------------------------------------------------------------------


def test_unknown_method_rejected():
    with pytest.raises(ValueError):
        validate_attack_fixture({**VALID, "method": "poison_evrything"})  # typo must not default


@pytest.mark.parametrize("method", ["poison_context", "poison_profile", "poison_notice_board"])
def test_each_known_method_accepted(method):
    assert validate_attack_fixture({**VALID, "method": method})["method"] == method


# --- typing & shape ----------------------------------------------------------------------------


def test_non_mapping_rejected():
    with pytest.raises(ValueError):
        validate_attack_fixture(["not", "a", "mapping"])


def test_wrong_field_type_rejected():
    with pytest.raises(ValueError):
        validate_attack_fixture({**VALID, "payload": 123})


def test_wrong_optional_field_type_rejected():
    with pytest.raises(ValueError):
        validate_attack_fixture({**VALID, "indicator": 123})


# --- payload size cap --------------------------------------------------------------------------


def test_oversized_payload_rejected():
    big = "A" * (MAX_ATTACK_PAYLOAD_BYTES + 1)
    with pytest.raises(ValueError):
        validate_attack_fixture({**VALID, "payload": big})


def test_payload_at_cap_accepted():
    at_cap = "A" * MAX_ATTACK_PAYLOAD_BYTES
    assert validate_attack_fixture({**VALID, "payload": at_cap})


def test_custom_cap_is_honored():
    with pytest.raises(ValueError):
        validate_attack_fixture({**VALID, "payload": "AAAA"}, max_payload_bytes=2)


# --- end-to-end classification -----------------------------------------------------------------


def test_run_with_unknown_method_classifies_attack_fixture_error(tmp_path):
    bad = {"name": "x", "method": "poison_typo", "target_tenant": "tenant_a", "payload": "p"}
    with pytest.raises(ValueError):
        run(make_scenario(), attack_fixture=bad, runs_dir=tmp_path, run_id="mtyp")
    end = [r for r in _records_from(tmp_path / "mtyp.run.jsonl") if r.get("outcome") == "end"]
    assert end and end[0]["run_outcome"] == "attack_fixture_error"
