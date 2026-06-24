"""Direct ``bulletin=`` constructor input is validated fail-closed (P0.3/P0.4).

A bulletin passed directly to the constructor must go through the same schema validator as
env/path/default-loaded bulletins — it is not a privileged bypass. Invalid input raises a
controlled ``BulletinValidationError`` at construction, before any model/tool/telemetry exposure.
"""

import pytest

from agent_deployment.bulletin import BulletinValidationError, default_bulletin
from agent_deployment.provider import AgentDeployment


def _invalid_cases():
    base = default_bulletin()
    missing = {k: v for k, v in base.items() if k != "summary"}            # missing required field
    empty = {**base, "summary": "   "}                                     # empty required field
    extra = {**base, "unexpected": "x"}                                    # additional property
    bad_priority = {**base, "priority": "urgent"}                          # invalid priority enum
    non_string = {**base, "summary": 123}                                  # non-string required field
    return {
        "missing_field": missing,
        "empty_field": empty,
        "additional_property": extra,
        "invalid_priority": bad_priority,
        "non_string_field": non_string,
    }


@pytest.mark.parametrize("name,obj", list(_invalid_cases().items()))
def test_invalid_direct_bulletin_fails_closed_in_init(name, obj):
    with pytest.raises(BulletinValidationError):
        AgentDeployment(bulletin=obj)


def test_non_object_bulletin_fails_closed():
    with pytest.raises(BulletinValidationError):
        AgentDeployment(bulletin=["not", "an", "object"])


@pytest.mark.parametrize("name,obj", list(_invalid_cases().items()))
def test_invalid_direct_bulletin_fails_closed_in_for_scenario(name, obj):
    with pytest.raises(BulletinValidationError):
        AgentDeployment.for_scenario("support_triage", bulletin=obj)


def test_valid_direct_bulletin_is_stored_and_normalized():
    custom = {**default_bulletin(), "bulletin_id": "b-custom", "priority": "elevated"}
    dep = AgentDeployment.for_scenario("support_triage", bulletin=custom)
    assert dep.bulletin["bulletin_id"] == "b-custom"
    assert dep.posture["posture_profile"] == "heightened"  # derived from elevated priority


def test_valid_direct_bulletin_runs_and_completes(tmp_path):
    dep = AgentDeployment.for_scenario("support_triage", bulletin=default_bulletin())
    report = dep.run(runs_dir=str(tmp_path), run_id="direct-bulletin")
    assert report.completed is True and report.compromised is False


def test_env_and_default_bulletin_paths_unaffected(tmp_path):
    # Default path still works (no direct bulletin).
    dep = AgentDeployment.for_scenario("support_triage")
    assert dep.bulletin["bulletin_id"] == "b-001"
