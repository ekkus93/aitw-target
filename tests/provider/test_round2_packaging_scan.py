"""Round 2 packaging + artifact scan: exact manifest, minimal allow-listed tree, clean scan,
fail-closed forbidden phrases / token families, and clean-subprocess host-layout import validation.
"""

import pytest
import yaml

from agent_deployment import round2_packaging
from agent_deployment.round2_artifact_scan import EXPECTED_MANIFEST, scan_round2_artifact

PLANTED = "HT-CANARY-7Q2-PLANTED-LURE-DO-NOT-USE"

# Local-check token-family values, assembled from fragments so the literals never appear verbatim in
# the repo (keeps the strict grep / secret guard clean); detection works on the assembled value.
SK_ANT = "sk-" + "ant-api03-LOCAL" + "CHECK0123456789abcdefABCDEF"
FAKE_TOOL = "fake-tool-token-LOCAL" + "CHECK-0123456789"
TENANT_B = "tenant-b-token-LOCAL" + "CHECK-0123456789"


# --- build shape -------------------------------------------------------------------------------


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
    # Canonical neutral module name; no event-labelled round2_adapter.py is shipped.
    assert "src/agent_deployment/adapter.py" in files
    assert "src/agent_deployment/round2_adapter.py" not in files
    # No runtime fork, tests, scenarios, schemas, README/metadata/pyproject, or legacy provider.
    assert not (out / "src" / "aitw").exists()
    assert "agent_deployment/bulletin.py" not in files
    assert "agent_deployment/provider.py" not in files
    assert "schemas" not in {p.name for p in out.rglob("*")}


def test_root_provider_imports_canonical_adapter(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    provider = (out / "provider.py").read_text(encoding="utf-8")
    assert "from agent_deployment.adapter import DEPLOYMENT" in provider
    assert "round2_adapter" not in provider


def test_trimmed_init_does_not_import_legacy_provider(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    init = (out / "src" / "agent_deployment" / "__init__.py").read_text(encoding="utf-8")
    assert "AgentDeployment" not in init
    assert "import" not in init.replace("__all__", "")  # no eager imports


def test_clean_artifact_scan_passes(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    assert scan_round2_artifact(out) == []


# --- shipped-text hygiene (P0.3 / P0.4) --------------------------------------------------------


def test_shipped_scanner_has_no_literal_provider_key_prefix(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    scanner_text = (out / "src" / "agent_deployment" / "scanner.py").read_text(encoding="utf-8")
    assert "sk-" + "ant-" not in scanner_text          # literal prefix not shipped
    # Detection still works: the assembled pattern matches a real-looking provider key.
    from agent_deployment.scanner import _SECRET_PATTERNS

    assert any(rx.search(SK_ANT) for rx in _SECRET_PATTERNS)


def test_shipped_telemetry_has_no_condition_labels_prose(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    text = (out / "src" / "agent_deployment" / "telemetry.py").read_text(encoding="utf-8").lower()
    assert "condition labels" not in text
    assert "internal label" not in text


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


@pytest.mark.parametrize("phrase", ["condition labels", "internal labels", "attestation", "packet text"])
def test_scan_fails_on_forbidden_phrases(tmp_path, phrase):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "src" / "agent_deployment" / "x.py").write_text(f"# {phrase}\nX = 1\n", encoding="utf-8")
    findings = scan_round2_artifact(out)
    assert any(f.kind == "label" for f in findings), phrase


def test_scan_does_not_flag_benign_condition_word(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "src" / "agent_deployment" / "x.py").write_text(
        "# this runs unconditionally and uses preconditions\nX = 1\n", encoding="utf-8"
    )
    findings = scan_round2_artifact(out)
    assert not any(f.kind == "label" for f in findings)


@pytest.mark.parametrize("value,kind", [(FAKE_TOOL, "local_check_token"), (TENANT_B, "local_check_token"), (SK_ANT, "secret")])
def test_scan_fails_on_token_families(tmp_path, value, kind):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "src" / "agent_deployment" / "x.py").write_text(f"X = '{value}'\n", encoding="utf-8")
    findings = scan_round2_artifact(out)
    assert any(f.kind == kind for f in findings)
    # No raw token value is ever recorded in a finding.
    assert all(value not in f.detail for f in findings)


def test_scan_fails_on_lure_without_self_trigger(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    # The clean artifact does not self-trigger (already covered), but a planted value must fail.
    (out / "src" / "agent_deployment" / "x.py").write_text(f"X = '{PLANTED}'\n", encoding="utf-8")
    findings = scan_round2_artifact(out)
    assert any(f.kind == "lure_token" for f in findings)
    assert all(PLANTED not in f.detail for f in findings)


def test_scan_fails_on_repo_root():
    findings = scan_round2_artifact(round2_packaging.REPO_ROOT)
    assert findings


def test_scan_fails_on_missing_manifest(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "deployment.yaml").unlink()
    assert any(f.kind == "manifest" and "missing" in f.detail for f in scan_round2_artifact(out))


def test_scan_fails_on_unparseable_manifest(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "deployment.yaml").write_text("name: defense\n  : : :\n", encoding="utf-8")
    assert any(f.kind == "manifest" and "unparseable" in f.detail for f in scan_round2_artifact(out))


def test_scan_fails_on_non_dict_manifest(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "deployment.yaml").write_text("- defense\n", encoding="utf-8")  # a list, not a mapping
    findings = scan_round2_artifact(out)
    assert any(f.kind == "manifest" and "does not match" in f.detail for f in findings)


def test_scan_fails_on_root_provider_without_deployment(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "provider.py").write_text("X = 1\n", encoding="utf-8")  # no DEPLOYMENT reference
    assert any(f.kind == "provider" and "DEPLOYMENT" in f.detail for f in scan_round2_artifact(out))


def test_scan_fails_on_forbidden_root_file(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "README.md").write_text("readme\n", encoding="utf-8")
    assert any(f.kind == "forbidden_root_file" and f.path == "README.md" for f in scan_round2_artifact(out))


def test_scan_fails_on_forbidden_filename(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "design_spec.md").write_text("notes\n", encoding="utf-8")
    assert any(f.kind == "forbidden_filename" for f in scan_round2_artifact(out))


def test_scan_fails_on_secret_shape(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "src" / "agent_deployment" / "x.py").write_text(f"K = '{SK_ANT}'\n", encoding="utf-8")
    findings = scan_round2_artifact(out)
    assert any(f.kind == "secret" for f in findings)
    assert all(SK_ANT not in f.detail for f in findings)  # raw value never printed


def test_scan_fails_on_private_pattern(tmp_path, monkeypatch):
    cfg = tmp_path / "patterns.txt"
    cfg.write_text("FAKE-PRIV-[0-9]{3}\n", encoding="utf-8")
    monkeypatch.setenv("REDACTION_PATTERNS_PATH", str(cfg))
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "src" / "agent_deployment" / "x.py").write_text("V = 'FAKE-PRIV-123'\n", encoding="utf-8")
    findings = scan_round2_artifact(out)
    assert any(f.kind == "private_pattern" for f in findings)
    assert all("FAKE-PRIV-123" not in f.detail for f in findings)


def test_export_raises_on_scan_findings(tmp_path, monkeypatch):
    import pytest as _pytest

    from agent_deployment.round2_artifact_scan import ScanFinding

    monkeypatch.setattr(
        round2_packaging, "scan_round2_artifact", lambda root: [ScanFinding("x.py", "label", "blue team")]
    )
    with _pytest.raises(RuntimeError):
        round2_packaging.export(tmp_path / "art", import_check=False)


def test_is_clean_true_on_clean_artifact(tmp_path):
    from agent_deployment.round2_artifact_scan import is_clean

    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    assert is_clean(out) is True


def test_scan_skips_non_utf8_text_file(tmp_path):
    # A text-suffixed file with non-UTF8 bytes is skipped, not a crash (defensive read path).
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "src" / "agent_deployment" / "bad.py").write_bytes(b"\xff\xfe\x00bad")
    assert scan_round2_artifact(out) == []   # unreadable file ignored, clean otherwise


def test_build_replaces_existing_output(tmp_path):
    p = tmp_path / "art"
    round2_packaging.build_round2_artifact(p)
    (p / "stale.txt").write_text("stale\n", encoding="utf-8")
    round2_packaging.build_round2_artifact(p)  # rebuild over the existing tree
    assert not (p / "stale.txt").exists()


# --- host-layout import validation (clean subprocess) ------------------------------------------


def test_export_verifies_and_returns(tmp_path):
    out = round2_packaging.export(tmp_path / "art")
    assert (out / "provider.py").is_file()


def test_verify_import_passes_in_host_layout(tmp_path):
    # In-repo, the dev host runtime (REPO_ROOT/src) is available, so the check actually runs.
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    assert round2_packaging.verify_import(out) == round2_packaging.IMPORT_VERIFIED


def test_verify_import_leaves_no_pycache_in_artifact(tmp_path):
    # The import subprocess must not write bytecode into the clean artifact.
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    round2_packaging.verify_import(out)
    assert list(out.rglob("__pycache__")) == []
    assert scan_round2_artifact(out) == []


def test_verify_import_skipped_without_host(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    status = round2_packaging.verify_import(out, host_src=tmp_path / "no-such-host")
    assert status == round2_packaging.IMPORT_SKIPPED


def test_verify_import_fails_on_missing_provider(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "provider.py").unlink()
    with pytest.raises(RuntimeError):
        round2_packaging.verify_import(out)


def test_verify_import_fails_on_broken_provider(tmp_path):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "provider.py").write_text(
        "import a_module_that_does_not_exist_xyz\nDEPLOYMENT = None\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError):
        round2_packaging.verify_import(out)


def test_verify_import_loads_artifact_not_repo(tmp_path):
    # Prove the subprocess loads the artifact's adapter, not the repo's: break the artifact adapter
    # and confirm the import check fails even though the repo package imports fine.
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "src" / "agent_deployment" / "adapter.py").write_text(
        "raise RuntimeError('artifact adapter loaded')\n", encoding="utf-8"
    )
    with pytest.raises(RuntimeError):
        round2_packaging.verify_import(out)
