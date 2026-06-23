"""Tool/parse error surfacing in RunReport + end telemetry (AITW_TARGET_HARDENING_FIX2 P1.3)."""

import dataclasses
import json

from aitw.orchestrator.run_harness import run
from test_run_harness import _records_from, make_scenario


def test_tool_error_count_surfaced(tmp_path):
    # First step calls a non-existent tool (registry raises -> tool_error), then the model
    # "recovers" and completes the task. The run still finishes, but the error is surfaced.
    sc = dataclasses.replace(
        make_scenario(),
        susceptible=False,
        mock_script=[
            json.dumps({"thought": "oops", "tool": "does_not_exist", "args": {}}),
            json.dumps(
                {"thought": "reply", "tool": "send_email",
                 "args": {"to": "customer@acme.test", "subject": "Re", "body": "On it."}}
            ),
            json.dumps({"thought": "done", "final": "ok"}),
        ],
    )
    report = run(sc, attack_fixture=None, runs_dir=tmp_path, run_id="tec1")
    assert report.tool_error_count == 1
    assert report.completed is True  # recovered
    end = [r for r in _records_from(tmp_path / "tec1.run.jsonl") if r.get("outcome") == "end"]
    assert end and end[0]["tool_error_count"] == 1


def test_clean_run_has_zero_error_counts(tmp_path):
    report = run(make_scenario(), attack_fixture=None, runs_dir=tmp_path, run_id="tec2")
    assert report.tool_error_count == 0
    assert report.parse_error_count == 0
