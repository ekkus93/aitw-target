"""Run-artifact containment tests (AITW_TARGET_HARDENING_FIX2 P0.2, P0.3).

The harness must refuse to follow symlinked run artifacts and must refuse to reuse a run_id
(no appending to a prior log, no reusing a prior workspace). These guard the experiment's
containment boundary: a run's bytes must land only inside its own fresh artifact set.
"""

from pathlib import Path

import pytest

from aitw.orchestrator.run_harness import run
from test_run_harness import make_scenario


def _run(tmp_path, run_id):
    return run(make_scenario(), attack_fixture=None, runs_dir=tmp_path, run_id=run_id)


# --- P0.3: run-id reuse fails loudly -----------------------------------------------------------


def test_reused_run_id_is_rejected(tmp_path):
    _run(tmp_path, "same")
    log = tmp_path / "same.run.jsonl"
    before = log.read_text()
    with pytest.raises(ValueError):
        _run(tmp_path, "same")  # second run with the same id must fail before running the task
    assert log.read_text() == before, "the original log must be left unchanged"


def test_first_run_has_exactly_one_start_and_end(tmp_path):
    report = _run(tmp_path, "once")
    records = [
        line for line in Path(report.log_path).read_text().splitlines() if line.strip()
    ]
    outcomes = [__import__("json").loads(r)["outcome"] for r in records]
    assert outcomes.count("start") == 1
    assert outcomes.count("end") == 1


def test_reuse_rejected_even_if_only_run_dir_exists(tmp_path):
    (tmp_path / "ghost").mkdir()
    with pytest.raises(ValueError):
        _run(tmp_path, "ghost")  # a leftover run dir (no log yet) still blocks reuse


# --- P0.2: symlinked artifacts are refused -----------------------------------------------------


def test_symlinked_log_pointing_outside_is_rejected(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    outside = tmp_path / "evil.jsonl"
    (runs / "sl.run.jsonl").symlink_to(outside)
    with pytest.raises(ValueError):
        _run(runs, "sl")
    assert not outside.exists(), "no bytes may be written through the symlink target"


def test_symlinked_run_dir_pointing_outside_is_rejected(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    outside = tmp_path / "evil_dir"
    outside.mkdir()
    (runs / "sl").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        _run(runs, "sl")
    assert not any(outside.iterdir()), "no workspace may be created inside the symlink target"


def test_symlinked_workspace_pointing_outside_is_rejected(tmp_path):
    runs = tmp_path / "runs"
    (runs / "sl").mkdir(parents=True)
    outside = tmp_path / "evil_ws"
    outside.mkdir()
    (runs / "sl" / "workspace").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        _run(runs, "sl")
    assert not any(outside.iterdir())


def test_symlinked_log_pointing_inside_is_still_rejected(tmp_path):
    # Even a symlink that resolves back inside runs_dir is an unexpected redirect we refuse.
    runs = tmp_path / "runs"
    runs.mkdir()
    inside = runs / "real.jsonl"
    (runs / "sl.run.jsonl").symlink_to(inside)
    with pytest.raises(ValueError):
        _run(runs, "sl")
