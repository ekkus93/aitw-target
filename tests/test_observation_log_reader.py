"""Reader/writer split for the telemetry log (AITW_TARGET_HARDENING_FIX2 P1.2).

Reading a missing log must RAISE and must not silently materialize an empty file; a reader has no
write handle.
"""

import pytest

from aitw.logging.observation_log import ObservationLog

TAGS = {"tenant": "t", "scenario": "s", "phase": "run"}


def test_read_existing_missing_raises_and_does_not_create(tmp_path):
    missing = tmp_path / "nope.run.jsonl"
    with pytest.raises(FileNotFoundError):
        ObservationLog.read_existing(missing)
    assert not missing.exists(), "reading a missing log must not create it"


def test_read_existing_reads_records(tmp_path):
    path = tmp_path / "r.jsonl"
    w = ObservationLog(path, create_new=True)
    w.emit_event(**TAGS, step_no=0, outcome="start", tool=None)
    w.emit_event(**TAGS, step_no=0, outcome="end", tool=None, completed=True, compromised=False)
    w.close()

    reader = ObservationLog.read_existing(path)
    records = reader.records()
    assert [r["outcome"] for r in records] == ["start", "end"]


def test_reader_cannot_write(tmp_path):
    path = tmp_path / "r.jsonl"
    ObservationLog(path, create_new=True).close()
    reader = ObservationLog.read_existing(path)
    with pytest.raises(RuntimeError):
        reader.emit_event(**TAGS, step_no=0, outcome="start", tool=None)


def test_create_new_refuses_existing_log(tmp_path):
    path = tmp_path / "r.jsonl"
    ObservationLog(path, create_new=True).close()
    with pytest.raises(FileExistsError):
        ObservationLog(path, create_new=True)  # exclusive create: no reopening over a prior log
