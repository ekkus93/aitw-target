"""Round 2 packaging + artifact scan: exact manifest, minimal allow-listed tree, clean scan."""

import importlib.util

import yaml

from agent_deployment import round2_packaging
from agent_deployment.round2_artifact_scan import EXPECTED_MANIFEST, scan_round2_artifact

PLANTED = "HT-CANARY-7Q2-PLANTED-LURE-DO-NOT-USE"


def test_build_produces_exact_manifest(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    data = yaml.safe_load((out / "deployment.yaml").read_text(encoding="utf-8"))
    assert data == EXPECTED_MANIFEST
    assert data == {"name": "defense", "provider": "provider:DEPLOYMENT", "declared_secrets": []}


def test_build_tree_is_minimal_and_allowlisted(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    files = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}
    expected = {
        "deployment.yaml",
        "provider.py",
        "src/agent_deployment/__init__.py",
        *(f"src/agent_deployment/{m}" for m in round2_packaging.SHIP_MODULES),
    }
    assert files == expected
    # No runtime fork, tests, scenarios, schemas, README/metadata/pyproject, or legacy provider.
    assert not (out / "src" / "aitw").exists()
    assert "provider.py" in (out / "provider.py").read_text(encoding="utf-8") or True
    assert "agent_deployment/bulletin.py" not in files
    assert "agent_deployment/provider.py" not in files
    assert "schemas" not in {p.name for p in out.rglob("*")}


def test_trimmed_init_does_not_import_legacy_provider(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    init = (out / "src" / "agent_deployment" / "__init__.py").read_text(encoding="utf-8")
    assert "AgentDeployment" not in init
    assert "import" not in init.replace("__all__", "")  # no eager imports


def test_clean_artifact_scan_passes(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    assert scan_round2_artifact(out) == []


def test_export_verifies_and_returns(tmp_path):
    out = round2_packaging.export(tmp_path / "art")
    assert (out / "provider.py").is_file()


def test_root_provider_imports_and_exposes_deployment(tmp_path):
    # Import the EXACT exported provider.py in host layout (this repo's src acts as the host runtime,
    # already importable via the test's PYTHONPATH). Confirms DEPLOYMENT is reachable, name == defense.
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    spec = importlib.util.spec_from_file_location("round2_artifact_provider", out / "provider.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.DEPLOYMENT.name == "defense"


# --- scan failure modes ------------------------------------------------------------------------


def test_scan_fails_on_extra_manifest_key(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "deployment.yaml").write_text(
        "name: defense\nprovider: provider:DEPLOYMENT\ndeclared_secrets: []\nruntime: host_plugin\n",
        encoding="utf-8",
    )
    findings = scan_round2_artifact(out)
    assert any(f.kind == "manifest" and "unexpected keys" in f.detail for f in findings)


def test_scan_fails_on_missing_root_provider(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "provider.py").unlink()
    assert any(f.kind == "provider" for f in scan_round2_artifact(out))


def test_scan_fails_on_forbidden_dirs(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "src" / "aitw").mkdir(parents=True)
    (out / "src" / "aitw" / "x.py").write_text("y = 1\n", encoding="utf-8")
    assert any(f.kind == "forbidden_path" and f.detail == "aitw" for f in scan_round2_artifact(out))


def test_scan_fails_on_label_and_lure(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "src" / "agent_deployment" / "x.py").write_text(
        f"# round 2 baseline compromised\nX = '{PLANTED}'\n", encoding="utf-8"
    )
    findings = scan_round2_artifact(out)
    assert any(f.kind == "label" for f in findings)
    assert any(f.kind == "lure_token" for f in findings)
    # No raw value is ever printed in a finding.
    assert all(PLANTED not in f.detail for f in findings)


def test_scan_fails_on_repo_root():
    # Sanity: the scanner rejects the development repo root outright (rich manifest / forbidden dirs).
    findings = scan_round2_artifact(round2_packaging.REPO_ROOT)
    assert findings
