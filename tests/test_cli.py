"""CLI behavior tests for scripts/run.py (AITW_TARGET_HARDENING TODO P0.2, P0.3, P1.8).

These run the real entry point as a subprocess so they assert on actual exit codes and stdout —
the layer where the measurement footguns live (silent no-attack runs, silent mock fallback).
They use the offline mock model only, so they pass in CI with no network or API key.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run.py"


def _run(args, tmp_path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--runs-dir", str(tmp_path), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def test_clean_no_attack_run_succeeds(tmp_path):
    p = _run(["--scenario", "support_triage"], tmp_path)
    assert p.returncode == 0, p.stderr
    report = json.loads(p.stdout)
    assert report["compromised"] is False
    assert report["model"] == "mock"


def test_valid_attack_run_succeeds(tmp_path):
    p = _run(
        ["--scenario", "support_triage", "--attack", str(ROOT / "attacks" / "example_attack.yaml")],
        tmp_path,
    )
    assert p.returncode == 0, p.stderr
    report = json.loads(p.stdout)
    assert report["attack"]  # attack name surfaced in the report


def test_missing_attack_path_fails_without_clean_report(tmp_path):
    p = _run(["--scenario", "support_triage", "--attack", "attacks/does_not_exist.yaml"], tmp_path)
    assert p.returncode != 0
    assert "does not exist" in p.stderr
    assert p.stdout.strip() == ""  # must NOT print a compromised=false clean report


def test_empty_attack_file_fails(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    p = _run(["--scenario", "support_triage", "--attack", str(empty)], tmp_path)
    assert p.returncode != 0
    assert "empty" in p.stderr


def test_malformed_attack_yaml_fails(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("key: [unclosed\n")
    p = _run(["--scenario", "support_triage", "--attack", str(bad)], tmp_path)
    assert p.returncode != 0
    assert "YAML" in p.stderr


def test_non_mapping_attack_yaml_fails(tmp_path):
    notmap = tmp_path / "list.yaml"
    notmap.write_text("- just\n- a\n- list\n")
    p = _run(["--scenario", "support_triage", "--attack", str(notmap)], tmp_path)
    assert p.returncode != 0
    assert "mapping" in p.stderr


def test_unknown_model_config_fails_and_lists_known(tmp_path):
    p = _run(["--scenario", "support_triage", "--model-config", "typoed_tenant"], tmp_path)
    assert p.returncode != 0
    assert "unknown --model-config" in p.stderr
    assert "tenant_a" in p.stderr  # error must list valid names/ids
    assert p.stdout.strip() == ""  # a typo must NOT silently produce a mock report


def test_explicit_mock_still_works(tmp_path):
    p = _run(["--scenario", "support_triage", "--model-config", "mock"], tmp_path)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["model"] == "mock"


def test_tenant_explicitly_configured_mock_resolves(tmp_path):
    # tenant_a in config/tenants.yaml explicitly declares adapter: mock — this is legitimate.
    p = _run(["--scenario", "support_triage", "--model-config", "tenant_a"], tmp_path)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["model"] == "mock"


def test_invalid_run_id_fails(tmp_path):
    p = _run(["--scenario", "support_triage", "--run-id", "../escape"], tmp_path)
    assert p.returncode != 0
    assert "run_id" in p.stderr
    assert p.stdout.strip() == ""
