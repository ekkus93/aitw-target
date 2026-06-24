"""Host lure-registry status visibility + required-mode fail-closed (P1.1/P1.2).

Uses fake, test-only loader callables — never real private values. Asserts the status taxonomy,
that required mode fails closed at construction, and that raw lure values never appear in the
status surfaces (telemetry / preflight / metadata).
"""

import json
import sys

import pytest

from agent_deployment import preflight  # noqa: F401  (used in preflight tests below)
from agent_deployment.provider import (
    AgentDeployment,
    HostLureRegistryError,
    _build_scanner,
    _load_host_lure_values,
)

# A fake, test-only lure value (never a real private value).
FAKE_LURE = "TEST-ONLY-LURE-VALUE-9Z"

_FAKE_MODULE = """\
FAKE_LURE = "TEST-ONLY-LURE-VALUE-9Z"
def good_loader():
    return {"canary": FAKE_LURE, "exfil_target": "a@b.test"}  # email excluded as a recipient
def raising_loader():
    raise RuntimeError("boom")
def bad_data_loader():
    return 12345  # not iterable / not a mapping -> failed
"""


@pytest.fixture(scope="module")
def fake_mod(tmp_path_factory):
    """Write an importable module of fake loaders and put it on sys.path; return its module name."""
    d = tmp_path_factory.mktemp("fakelure")
    (d / "fake_lure_loaders.py").write_text(_FAKE_MODULE, encoding="utf-8")
    sys.path.insert(0, str(d))
    try:
        yield "fake_lure_loaders"
    finally:
        sys.path.remove(str(d))
        sys.modules.pop("fake_lure_loaders", None)


# --- status taxonomy --------------------------------------------------------------------------


def test_status_skipped_when_unset():
    values, status = _load_host_lure_values({})
    assert status == "skipped" and values == frozenset()


def test_status_active_when_loaded(fake_mod):
    values, status = _load_host_lure_values({"HOST_LURE_REGISTRY": f"{fake_mod}:good_loader"})
    assert status == "active"
    assert FAKE_LURE in values
    assert "a@b.test" not in values  # email-shaped recipient excluded


def test_status_unavailable_when_module_missing():
    _, status = _load_host_lure_values({"HOST_LURE_REGISTRY": "no.such.module:fn"})
    assert status == "unavailable"


def test_status_failed_when_loader_raises(fake_mod):
    _, status = _load_host_lure_values({"HOST_LURE_REGISTRY": f"{fake_mod}:raising_loader"})
    assert status == "failed"


def test_status_failed_on_bad_data(fake_mod):
    _, status = _load_host_lure_values({"HOST_LURE_REGISTRY": f"{fake_mod}:bad_data_loader"})
    assert status == "failed"


# --- required mode fails closed at construction -----------------------------------------------


def test_required_mode_active_is_allowed(fake_mod):
    scanner, status = _build_scanner(
        {"HOST_LURE_REGISTRY": f"{fake_mod}:good_loader", "HOST_LURE_REGISTRY_REQUIRED": "1"}
    )
    assert status == "active" and FAKE_LURE in scanner.extra_literals


def test_required_mode_non_active_fails_closed(fake_mod):
    for spec in ("no.such.module:fn", f"{fake_mod}:raising_loader", None):
        env = {"HOST_LURE_REGISTRY_REQUIRED": "1"}
        if spec is not None:
            env["HOST_LURE_REGISTRY"] = spec
        with pytest.raises(HostLureRegistryError):
            _build_scanner(env)


def test_required_mode_blocks_provider_construction():
    with pytest.raises(HostLureRegistryError):
        AgentDeployment(env={"HOST_LURE_REGISTRY_REQUIRED": "1"})  # unset registry + required


def test_optional_unavailable_does_not_block_construction():
    dep = AgentDeployment.for_scenario(
        "support_triage", env={"HOST_LURE_REGISTRY": "no.such.module:fn"}
    )
    assert dep.host_lure_status == "unavailable"


# --- visibility: telemetry + preflight, never raw values --------------------------------------


def test_run_emits_status_telemetry_without_raw_value(tmp_path, fake_mod):
    dep = AgentDeployment.for_scenario(
        "support_triage", env={"HOST_LURE_REGISTRY": f"{fake_mod}:good_loader"}
    )
    report = dep.run(runs_dir=str(tmp_path), run_id="lure-status")
    text = open(report.log_path).read()
    records = [json.loads(line) for line in text.splitlines() if line.strip()]
    status_evs = [r for r in records if r.get("reason") == "host_lure_registry_status"]
    assert status_evs and status_evs[0]["host_lure_registry_status"] == "active"
    assert status_evs[0]["host_lure_registry_count"] >= 1
    assert FAKE_LURE not in text  # raw value never persisted (redacting log + count-only event)


def test_preflight_check_reports_status_without_raw_value(fake_mod):
    active = preflight.check_host_lure_registry({"HOST_LURE_REGISTRY": f"{fake_mod}:good_loader"})
    assert active.ok and "active" in active.actual
    assert FAKE_LURE not in active.actual

    skipped = preflight.check_host_lure_registry({})
    assert skipped.skipped and "skipped" in skipped.actual

    failed_required = preflight.check_host_lure_registry(
        {"HOST_LURE_REGISTRY": "no.such.module:fn", "HOST_LURE_REGISTRY_REQUIRED": "1"}
    )
    assert not failed_required.ok and not failed_required.skipped  # required -> FAIL


def test_metadata_records_build_scope_only(tmp_path, monkeypatch):
    from agent_deployment.metadata import dependency_metadata

    monkeypatch.delenv("HOST_LURE_REGISTRY", raising=False)
    meta = dependency_metadata()
    assert meta["host_lure_registry_configured_at_build"] is False
    assert meta["host_lure_registry_status_scope"] == "build_environment_only"
    assert FAKE_LURE not in json.dumps(meta)
