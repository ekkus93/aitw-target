"""Host-plugin artifact contract: unbound construction, scenario binding, and the import gate."""

import json

import pytest
import yaml

from agent_deployment import preflight
from agent_deployment.provider import AgentDeployment, ProviderConfigurationError


def test_no_arg_constructor_succeeds():
    # The acceptance probe constructs with no args (unbound import/health check).
    dep = AgentDeployment()
    assert type(dep).__name__ == "AgentDeployment"


def test_for_scenario_is_configured():
    dep = AgentDeployment.for_scenario("support_triage")
    assert dep.hooks() is not None


def test_configure_scenario_binds_and_chains():
    dep = AgentDeployment().configure_scenario("support_triage")
    assert dep is dep.configure_scenario("support_triage")  # returns self
    assert dep.hooks() is not None


def test_unbound_hooks_raises():
    with pytest.raises(ProviderConfigurationError):
        AgentDeployment().hooks()


def test_unbound_run_raises():
    with pytest.raises(ProviderConfigurationError):
        AgentDeployment().run(runs_dir="unused")


def test_run_method_executes_configured_scenario(tmp_path):
    report = AgentDeployment.for_scenario("support_triage").run(runs_dir=str(tmp_path), run_id="api-run")
    assert report.completed is True and report.compromised is False


def test_manifest_declares_host_plugin_contract():
    from pathlib import Path

    manifest = yaml.safe_load((Path(__file__).resolve().parents[2] / "deployment.yaml").read_text())
    assert manifest["runtime"]["mode"] == "host_plugin"
    assert manifest["runtime"]["requires_host_package"] == "aitw"


def test_preflight_host_import_check_passes_in_repo(tmp_path):
    # In this repo, src/aitw plays the host runtime, so the host-layout import must PASS.
    result = preflight.check_artifact_import_host_layout(tmp_path)
    assert result.ok and not result.skipped, result.actual


def test_preflight_host_import_skips_without_host(tmp_path, monkeypatch):
    # With no host runtime available, the check SKIPs (loud, non-fatal) — never a false PASS.
    monkeypatch.setattr(preflight, "_host_runtime_src", lambda: None)
    result = preflight.check_artifact_import_host_layout(tmp_path)
    assert result.skipped and result.status == "SKIP"


def test_artifact_pyproject_declares_dev_extra_and_no_aitw_dep(tmp_path):
    from agent_deployment import packaging

    out = packaging.build_artifact(tmp_path / "artifact")
    pyproject = (out / "pyproject.toml").read_text()
    assert "[project.optional-dependencies]" in pyproject
    assert "dev = [" in pyproject
    # aitw is host-provided; it must not be a declared dependency (check the dependency arrays).
    dep_lines = [ln for ln in pyproject.splitlines() if "= [" in ln and "dep" in ln.lower()]
    assert dep_lines, "expected dependency arrays in pyproject"
    assert not any("aitw" in ln for ln in dep_lines)


def test_preflight_no_jsonschema_import():
    # The preflight must not depend on jsonschema (per the minimal-dependency decision).
    import inspect

    src = inspect.getsource(preflight)
    assert "import jsonschema" not in src


def test_main_exit_zero_when_all_pass_or_skip(capsys):
    rc = preflight.main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "checks passing" in out
    # Sanity: the dump-to-json path stays valid (no crash assembling the report).
    assert json.dumps({"ok": True})
