"""Clean export packaging and the artifact sanitization scan."""

import py_compile
from pathlib import Path

from agent_deployment import packaging
from agent_deployment.artifact_scan import is_clean, scan_artifact

REPO_ROOT = Path(__file__).resolve().parents[2]

# Built by concatenation so the credential-shaped literal never appears contiguously in source.
FAKE_KEY = "sk-" + "ant-" + "abcdefghijklmnopqrstuvwxyz0123"


def _build(tmp_path):
    return packaging.build_artifact(tmp_path / "artifact")


def test_artifact_contains_expected_files(tmp_path):
    out = _build(tmp_path)
    assert (out / "deployment.yaml").exists()
    assert (out / "schemas" / "operational_bulletin.schema.json").exists()
    assert (out / "README.md").exists()
    assert (out / "pyproject.toml").exists()
    pkg = out / "src" / "agent_deployment"
    for module in ("provider.py", "scanner.py", "bulletin.py", "registry.py", "reset.py", "run_local.py"):
        assert (pkg / module).exists(), module


def test_artifact_excludes_dev_tools_and_runtime_fork(tmp_path):
    out = _build(tmp_path)
    pkg = out / "src" / "agent_deployment"
    # Build/dev tools must not ship.
    for module in ("packaging.py", "artifact_scan.py", "evidence.py", "readme.py"):
        assert not (pkg / module).exists(), f"{module} should not ship"
    # The underlying runtime fork must not be bundled.
    assert not (out / "src" / "aitw").exists()
    # No operator docs, attacks, or tests.
    assert not (out / "docs").exists()
    assert not (out / "attacks").exists()
    assert not (out / "tests").exists()


def test_artifact_modules_compile(tmp_path):
    out = _build(tmp_path)
    for py in (out / "src" / "agent_deployment").glob("*.py"):
        py_compile.compile(str(py), doraise=True)


def test_artifact_passes_sanitization_scan(tmp_path):
    out = _build(tmp_path)
    findings = scan_artifact(out)
    assert findings == [], f"artifact should be clean, got: {findings}"
    assert is_clean(out)


def test_export_verifies_and_returns_clean_artifact(tmp_path):
    out = packaging.export(tmp_path / "artifact", verify=True)
    assert is_clean(out)


def test_scan_flags_the_runtime_fork(tmp_path):
    # Scanning the underlying fork must FAIL (path tell + intentional-weakness language).
    findings = scan_artifact(REPO_ROOT / "src" / "aitw")
    assert findings, "scan must flag the runtime fork"
    kinds = {f.kind for f in findings}
    assert "forbidden_path" in kinds  # the 'aitw' path component


def test_scan_flags_injected_label(tmp_path):
    d = tmp_path / "probe"
    d.mkdir()
    (d / "note.md").write_text("This system is naive by design.", encoding="utf-8")
    findings = scan_artifact(d)
    assert any(f.kind == "label" for f in findings)


def test_scan_flags_injected_secret(tmp_path):
    d = tmp_path / "probe"
    d.mkdir()
    (d / "cfg.txt").write_text(f"token={FAKE_KEY}", encoding="utf-8")
    findings = scan_artifact(d)
    assert any(f.kind == "secret" for f in findings)


def test_vendored_schema_id_is_exempt_from_label_scan(tmp_path):
    # The canonical schema's $id contains an event domain but is kept verbatim by contract; it must
    # be exempt from the label scan (still present in the clean artifact).
    out = _build(tmp_path)
    schema_text = (out / "schemas" / "operational_bulletin.schema.json").read_text()
    assert "day-zero.dev" in schema_text          # kept verbatim
    assert scan_artifact(out) == []               # yet the artifact still scans clean
