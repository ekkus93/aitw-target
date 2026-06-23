"""Telemetry redaction + truncation tests (AITW_TARGET_HARDENING_FIX2 P1.7)."""

import json

from aitw.logging.observation_log import ObservationLog

TAGS = {"tenant": "t", "scenario": "s", "phase": "run", "step_no": 0, "outcome": "x", "tool": None}


def _roundtrip(tmp_path, **fields):
    path = tmp_path / "t.jsonl"
    log = ObservationLog(path, create_new=True)
    log.emit_event(**TAGS, **fields)
    log.close()
    return ObservationLog.read_existing(path).records()[0]


def test_secret_value_is_redacted(tmp_path):
    fake = "sk-ant-" + "A" * 40
    rec = _roundtrip(tmp_path, note=fake)
    blob = json.dumps(rec)
    assert fake not in blob
    assert "[REDACTED-SECRET]" in blob


def test_long_field_is_truncated_with_metadata(tmp_path):
    rec = _roundtrip(tmp_path, note="B" * 100_000)
    assert len(rec["note"].encode("utf-8")) < 100_000
    assert "truncated" in rec["note"] and "sha=" in rec["note"]


def test_event_size_cap_drops_oversized_fields(tmp_path):
    rec = _roundtrip(tmp_path, big=["X" * 8000 for _ in range(20)])
    assert "_event_truncated" in rec
    assert "big" not in rec
    # Required tags survive even when the event is truncated.
    assert rec["tenant"] == "t" and rec["outcome"] == "x"


def test_unsafe_full_telemetry_opt_in_disables_redaction(tmp_path, monkeypatch):
    monkeypatch.setenv("AITW_UNSAFE_FULL_TELEMETRY", "1")
    fake = "sk-ant-" + "A" * 40
    rec = _roundtrip(tmp_path, note=fake)
    assert fake in json.dumps(rec)  # opt-in escape hatch keeps the raw payload
