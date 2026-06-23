"""Durability of the telemetry log reader.

The log is the only record of a run's verdict. A torn/partial final line (e.g. a crash mid-write)
must not abort the whole read and take down aggregation across a batch.
"""

import json

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
