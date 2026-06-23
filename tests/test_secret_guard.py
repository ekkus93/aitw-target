# secret-guard:allow-pattern-literals
"""Tests for the CI secret + IP-leak guard.

Required behaviours:
  - a hardcoded key VALUE fails the scan,
  - the normal `os.environ["ANTHROPIC_API_KEY"]` reference passes,
  - a missing local pattern file emits a LOUD stderr notice (never a silent pass).

Fake secret material is constructed by concatenation at runtime so the literal never
appears contiguously in this (tracked, scanned) source file.
"""

from pathlib import Path

from aitw.safety import secret_guard


def test_hardcoded_key_value_fails():
    fake = "sk-" + "ant-api03-" + "A" * 40  # never a contiguous literal in this file
    violations = secret_guard.scan_text(f'ANTHROPIC_API_KEY = "{fake}"')
    assert violations, "a hardcoded key value must be flagged"
    labels = {label for _, label, _ in violations}
    assert "anthropic-key-literal" in labels


def test_env_reference_passes():
    code = 'api_key = os.environ["ANTHROPIC_API_KEY"]'
    assert secret_guard.scan_text(code) == [], "env-access reference must pass"


def test_getenv_reference_passes():
    code = 'token = os.getenv("TOOL_LAYER_TOKEN", "")'
    assert secret_guard.scan_text(code) == []


def test_hardcoded_generic_token_fails():
    secret = "token = " + '"' + "x" * 24 + '"'  # `token = "xxxxxxxx..."` hardcoded literal
    violations = secret_guard.scan_text(secret)
    labels = {label for _, label, _ in violations}
    assert "hardcoded-credential-assignment" in labels


def test_patent_leak_class_fails():
    assert secret_guard.scan_text("# Patent Family: 3")
    assert secret_guard.scan_text("filed with the USPTO last year")
    assert secret_guard.scan_text("provisional 63/000,000 on file")


def test_clean_text_passes():
    assert secret_guard.scan_text("def add(a, b):\n    return a + b\n") == []


def test_missing_local_file_is_loud(monkeypatch, capsys):
    monkeypatch.setattr(
        secret_guard, "LOCAL_PATTERN_FILE", Path("/nonexistent/secret_guard_local.yaml")
    )
    result = secret_guard.load_local_patterns()
    assert result == []
    err = capsys.readouterr().err
    assert "not found" in err
    assert "generic patterns only" in err


def test_repo_scan_is_clean():
    """The committed repo itself must pass the guard."""
    findings, scanned = secret_guard.scan_repo()
    assert findings == {}, f"repo is not clean: {findings}"
    assert scanned > 0


# --- suppression marker is restricted to approved paths (P0.5) --------------------------------


def test_marker_in_approved_path_suppresses_scan():
    approved = next(iter(secret_guard.MARKER_ALLOWED_PATHS))
    fake = "sk-" + "ant-api03-" + "A" * 40
    text = f'{secret_guard.ALLOW_MARKER}\nANTHROPIC_API_KEY = "{fake}"\n'
    assert secret_guard.evaluate_file(approved, text) == []


def test_marker_in_unapproved_path_is_a_violation():
    text = f"# {secret_guard.ALLOW_MARKER}\njust some notes\n"
    labels = {label for _, label, _ in secret_guard.evaluate_file("docs/notes.md", text)}
    assert "unauthorized-suppression-marker" in labels


def test_marker_does_not_hide_secret_in_unapproved_path():
    # The whole point of P0.5: adding the marker to a random file must NOT bypass the scan.
    fake = "sk-" + "ant-api03-" + "A" * 40
    text = f'{secret_guard.ALLOW_MARKER}\nANTHROPIC_API_KEY = "{fake}"\n'
    labels = {label for _, label, _ in secret_guard.evaluate_file("evil/sneaky.py", text)}
    assert "unauthorized-suppression-marker" in labels
    assert "anthropic-key-literal" in labels  # secret still caught despite the marker


def test_unapproved_marker_reports_its_line_number():
    text = f"line one\nline two\n{secret_guard.ALLOW_MARKER}\n"
    violations = secret_guard.evaluate_file("docs/x.md", text)
    marker = next(v for v in violations if v[1] == "unauthorized-suppression-marker")
    assert marker[0] == 3
