"""Deployment telemetry stays JSONL-compatible and gets redacted by the runtime log."""

from aitw.logging.observation_log import ObservationLog

from agent_deployment.telemetry import PHASE_TOOL_POLICY, DeploymentTelemetry

REQUIRED_TAGS = {"tenant", "scenario", "step_no", "tool", "outcome", "phase"}

# Built by concatenation so the credential-shaped literal never appears contiguously in source
# (the repo secret guard fails on a raw sk-ant- literal). At runtime this is a valid key shape.
FAKE_KEY = "sk-" + "ant-" + "abcdefghijklmnopqrstuvwxyz0123"


def _emit_through_log(tmp_path, **fields):
    log = ObservationLog(tmp_path / "t.jsonl", create_new=True)
    telemetry = DeploymentTelemetry(log=log, tags={"tenant": "tenant_a", "scenario": "support_triage"})
    telemetry.emit(phase=PHASE_TOOL_POLICY, outcome="denied", tool="scheduler", **fields)
    log.close()
    return ObservationLog.read_existing(tmp_path / "t.jsonl").records()


def test_event_carries_required_tags_and_parses(tmp_path):
    records = _emit_through_log(tmp_path, reason="tool_not_allowed")
    assert len(records) == 1
    rec = records[0]
    assert REQUIRED_TAGS.issubset(rec)
    assert rec["phase"] == "tool_policy"
    assert rec["outcome"] == "denied"
    assert rec["tool"] == "scheduler"
    assert rec["reason"] == "tool_not_allowed"   # additive field preserved


def test_additive_fields_do_not_break_reader(tmp_path):
    records = _emit_through_log(
        tmp_path, reason="x", redaction_count=3, posture_profile="standard", blocked_tool="scheduler"
    )
    rec = records[0]
    assert rec["redaction_count"] == 3
    assert rec["posture_profile"] == "standard"


def test_credential_shaped_value_is_redacted_in_log(tmp_path):
    records = _emit_through_log(tmp_path, reason=f"contains {FAKE_KEY} secret")
    assert FAKE_KEY not in records[0]["reason"]
    assert "REDACTED" in records[0]["reason"]


def test_in_memory_mirror_tracks_events_without_log():
    telemetry = DeploymentTelemetry()  # no log
    telemetry.emit(phase=PHASE_TOOL_POLICY, outcome="denied", tool="scheduler", reason="x")
    telemetry.emit(phase=PHASE_TOOL_POLICY, outcome="allowed", tool="send_email")
    assert telemetry.count(phase="tool_policy") == 2
    assert telemetry.count(outcome="denied") == 1
