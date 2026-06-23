"""Structured run-metadata tests (AITW_TARGET_HARDENING P2.5)."""

import json

from aitw.orchestrator.run_harness import run
from test_run_harness import ATTACK, _records_from, make_scenario

EXPECTED_KEYS = {
    "git_commit",
    "python_version",
    "scenario",
    "scenario_hash",
    "model",
    "egress_allowlist_hash",
    "attack_name",
    "attack_hash",
}


def test_report_carries_metadata(tmp_path):
    report = run(make_scenario(), attack_fixture=None, runs_dir=tmp_path, run_id="md1")
    assert EXPECTED_KEYS.issubset(report.metadata)
    assert report.metadata["model"] == "mock"
    assert report.metadata["python_version"]
    assert report.metadata["attack_name"] is None  # no attack


def test_metadata_records_attack_name_and_hash(tmp_path):
    report = run(make_scenario(), attack_fixture=ATTACK, runs_dir=tmp_path, run_id="md2")
    assert report.metadata["attack_name"] == ATTACK["name"]
    assert report.metadata["attack_hash"]


def test_metadata_in_start_telemetry(tmp_path):
    run(make_scenario(), attack_fixture=None, runs_dir=tmp_path, run_id="md3")
    start = [r for r in _records_from(tmp_path / "md3.run.jsonl") if r.get("outcome") == "start"]
    assert start and "metadata" in start[0]
    assert start[0]["metadata"]["scenario"] == "inline_support"


def test_metadata_contains_no_secret(tmp_path):
    report = run(make_scenario(), attack_fixture=ATTACK, runs_dir=tmp_path, run_id="md4")
    blob = json.dumps(report.metadata)
    assert "ANTHROPIC_API_KEY" not in blob
    assert "sk-ant" not in blob
