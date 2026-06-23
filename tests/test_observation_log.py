"""Durability of the telemetry log reader.

The log is the only record of a run's verdict. A torn/partial final line (e.g. a crash mid-write)
must not abort the whole read and take down aggregation across a batch.
"""

import json

import pytest

from aitw.logging.observation_log import ObservationLog

TAGS = {"tenant": "t", "scenario": "s", "phase": "run"}


def test_records_skips_torn_trailing_line(tmp_path):
    path = tmp_path / "run.jsonl"
    log = ObservationLog(path)
    log.emit_event(**TAGS, step_no=0, outcome="start", tool=None)
    log.emit_event(**TAGS, step_no=0, outcome="end", tool=None, completed=True, compromised=False)
    log.close()
    # Simulate a crash mid-write that left a partial JSON object as the last line.
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"tenant": "t", "scenario": ')

    records = ObservationLog(path).records()

    assert len(records) == 2, "the two complete records must survive a torn trailing line"
    assert [r["outcome"] for r in records] == ["start", "end"]


def test_records_reads_all_wellformed_lines(tmp_path):
    path = tmp_path / "run.jsonl"
    log = ObservationLog(path)
    for i in range(3):
        log.emit_event(**TAGS, step_no=i, outcome="step", tool="file_io")
    log.close()
    assert len(ObservationLog(path).records()) == 3
    assert all(json.dumps(r) for r in ObservationLog(path).records())


def test_records_raises_on_malformed_middle_line(tmp_path):
    # Mid-log corruption must NOT be silently skipped — that would hide dropped records from
    # scoring. Only a torn *final* line is tolerated.
    path = tmp_path / "run.jsonl"
    log = ObservationLog(path)
    log.emit_event(**TAGS, step_no=0, outcome="start", tool=None)
    log.close()
    with path.open("a", encoding="utf-8") as fh:
        fh.write("{not json}\n")  # corrupt middle line
        fh.write(json.dumps({"tenant": "t", "scenario": "s", "phase": "run", "ok": True}) + "\n")
    with pytest.raises(ValueError) as exc:
        ObservationLog(path).records()
    assert "malformed telemetry record" in str(exc.value)


def test_records_reports_physical_line_number_ignoring_blanks(tmp_path):
    # Blank lines before/after the corruption must not skew the reported physical line number.
    path = tmp_path / "run.jsonl"
    good = json.dumps({"tenant": "t", "scenario": "s", "phase": "run", "ok": True})
    # line 1: good, line 2: blank, line 3: corrupt, line 4: blank, line 5: good (final)
    path.write_text(f"{good}\n\n{{bad}}\n\n{good}\n")
    with pytest.raises(ValueError) as exc:
        ObservationLog(path).records()
    assert f"{path}:3" in str(exc.value)


def test_records_tolerates_torn_final_line_even_with_trailing_blanks(tmp_path):
    path = tmp_path / "run.jsonl"
    good = json.dumps({"tenant": "t", "scenario": "s", "phase": "run", "ok": True})
    path.write_text(f"{good}\n{{torn\n\n")  # torn final non-blank line, then a trailing blank
    records = ObservationLog(path).records()
    assert len(records) == 1
    assert records[0]["ok"] is True
