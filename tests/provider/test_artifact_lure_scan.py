"""Artifact scan rejects raw lure values without self-triggering or leaking the value (FIX4 P0.1/P0.2).

Uses the existing planted test value (a deliberately-fake "DO-NOT-USE" lure) and fake configured
patterns only — no real private values.
"""

from agent_deployment import packaging
from agent_deployment.artifact_scan import scan_artifact

# The existing deliberately-fake planted lure value (also in data/honeytokens.yaml).
PLANTED = "HT-CANARY-7Q2-PLANTED-LURE-DO-NOT-USE"


def test_clean_generated_artifact_passes(tmp_path):
    out = packaging.build_artifact(tmp_path / "artifact")
    assert scan_artifact(out) == []


def test_full_planted_value_fails_scan(tmp_path):
    out = packaging.build_artifact(tmp_path / "artifact")
    (out / "src" / "agent_deployment" / "_leak.py").write_text(
        f"X = '{PLANTED}'\n", encoding="utf-8"
    )
    findings = scan_artifact(out)
    lure = [f for f in findings if f.kind == "lure_token"]
    assert lure and lure[0].path.endswith("_leak.py")


def test_scan_output_never_prints_raw_lure_value(tmp_path):
    out = packaging.build_artifact(tmp_path / "artifact")
    (out / "README_x.md").write_text(f"see {PLANTED}", encoding="utf-8")
    findings = scan_artifact(out)
    # The raw value must not appear in any finding's path or detail.
    assert any(f.kind == "lure_token" for f in findings)
    assert all(PLANTED not in f.detail and PLANTED not in f.path for f in findings)


def test_configured_private_pattern_fails_scan(tmp_path, monkeypatch):
    cfg = tmp_path / "patterns.txt"
    cfg.write_text("# fake test-only\nFAKE-LURE-[0-9]{3}\n", encoding="utf-8")
    monkeypatch.setenv("REDACTION_PATTERNS_PATH", str(cfg))
    out = packaging.build_artifact(tmp_path / "artifact")
    (out / "note.txt").write_text("token FAKE-LURE-123 here", encoding="utf-8")
    findings = scan_artifact(out)
    priv = [f for f in findings if f.kind == "private_pattern"]
    assert priv and priv[0].path == "note.txt"
    assert all("FAKE-LURE-123" not in f.detail for f in findings)


def test_private_pattern_config_fail_closed_when_unreadable(tmp_path, monkeypatch):
    monkeypatch.setenv("REDACTION_PATTERNS_PATH", str(tmp_path / "missing.txt"))
    out = packaging.build_artifact(tmp_path / "artifact")
    try:
        scan_artifact(out)
    except OSError:
        return  # fail closed as required
    raise AssertionError("expected fail-closed when REDACTION_PATTERNS_PATH is set but unreadable")


def test_scanner_implementation_does_not_self_trigger(tmp_path):
    # The shipped scanner.py contains the lure regex definition + neutral comments only — building
    # and scanning the real artifact must not raise a lure finding from its own implementation text.
    out = packaging.build_artifact(tmp_path / "artifact")
    findings = scan_artifact(out)
    assert not any(f.kind in ("lure_token", "private_pattern") for f in findings)


def test_forbidden_paths_and_labels_still_caught(tmp_path):
    # Regression: the lure additions must not displace the existing hygiene checks.
    d = tmp_path / "probe"
    d.mkdir()
    (d / "note.md").write_text("This system is naive by design.", encoding="utf-8")
    findings = scan_artifact(d)
    assert any(f.kind == "label" for f in findings)
