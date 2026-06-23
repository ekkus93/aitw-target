"""Attack-fixture validation tests (AITW_TARGET_HARDENING P2.3)."""

import pytest

from aitw.orchestrator.attack_fixture import validate_attack_fixture
from aitw.orchestrator.run_harness import run
from test_run_harness import _records_from, make_scenario


def test_none_passes_through():
    assert validate_attack_fixture(None) is None


def test_valid_fixture_returns_unchanged():
    fx = {"name": "x", "method": "poison_context", "target_tenant": "t", "payload": "p", "indicator": "i"}
    assert validate_attack_fixture(fx) is fx


def test_absent_method_is_allowed():
    assert validate_attack_fixture({"payload": "p"}) == {"payload": "p"}


def test_unknown_method_rejected():
    with pytest.raises(ValueError):
        validate_attack_fixture({"method": "poison_evrything"})  # typo must not default silently


def test_non_mapping_rejected():
    with pytest.raises(ValueError):
        validate_attack_fixture(["not", "a", "mapping"])


def test_wrong_field_type_rejected():
    with pytest.raises(ValueError):
        validate_attack_fixture({"method": "poison_context", "payload": 123})


def test_run_with_unknown_method_classifies_attack_fixture_error(tmp_path):
    bad = {"name": "x", "method": "poison_typo", "target_tenant": "tenant_a", "payload": "p"}
    with pytest.raises(ValueError):
        run(make_scenario(), attack_fixture=bad, runs_dir=tmp_path, run_id="mtyp")
    end = [r for r in _records_from(tmp_path / "mtyp.run.jsonl") if r.get("outcome") == "end"]
    assert end and end[0]["run_outcome"] == "attack_fixture_error"
