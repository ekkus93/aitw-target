"""run_id containment tests.

run_id becomes part of on-disk paths (the run log and the workspace dir). A user- or
caller-supplied id must never traverse out of runs_dir, and the same validation must apply to
generated ids. See AITW_TARGET_HARDENING_SPEC §4.1 / TODO P0.1.
"""

import json

import pytest

from aitw.orchestrator.run_harness import _now_id, _validate_run_id, run
from test_run_harness import make_scenario

# Each of these must be rejected before any path is built.
REJECTED = [
    "",          # empty
    ".",         # dot-only
    "..",        # parent dir
    "...",       # still dot traversal-ish; not a valid slug
    ".hidden",   # leading dot
    "../escape", # classic traversal (caught by the separator)
    "a/b",       # forward separator
    "a\\b",      # backslash separator
    "/tmp/x",    # absolute path
    "a..b",      # '..' embedded — regex alone would accept this
    "bad\nid",   # control character
]


@pytest.mark.parametrize("bad", REJECTED)
def test_validate_run_id_rejects(bad):
    with pytest.raises(ValueError):
        _validate_run_id(bad)


@pytest.mark.parametrize(
    "good",
    [
        "support-20260622T123000.001",  # user-supplied valid id
        "t1",
        "run.123",
        "A-b_c.9",
    ],
)
def test_validate_run_id_accepts(good):
    assert _validate_run_id(good) == good


def test_generated_id_passes_validator():
    # Regression: the generated id format must always satisfy the same validator.
    assert _validate_run_id(_now_id("support_triage")).startswith("support_triage-")


@pytest.mark.parametrize("bad", ["../escape", "a/b", "a\\b", "/tmp/x", ".."])
def test_run_rejects_bad_run_id_and_writes_nothing(tmp_path, bad):
    before = set(tmp_path.iterdir())
    with pytest.raises(ValueError):
        run(make_scenario(), attack_fixture=None, runs_dir=tmp_path, run_id=bad)
    # No log file or workspace dir may be created for a rejected id.
    assert set(tmp_path.iterdir()) == before


def test_run_with_empty_run_id_generates_valid_one(tmp_path):
    report = run(make_scenario(), attack_fixture=None, runs_dir=tmp_path, run_id=None)
    assert report.completed is True
    # Log + workspace must live under runs_dir.
    log = (tmp_path / f"{report.run_id}.run.jsonl").resolve()
    assert log.is_relative_to(tmp_path.resolve())
    assert (tmp_path / report.run_id / "workspace").resolve().is_relative_to(tmp_path.resolve())
    # And the run actually produced telemetry.
    assert any(json.loads(line) for line in log.read_text().splitlines() if line.strip())
