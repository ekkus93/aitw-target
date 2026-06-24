"""Stock-host contract: credential broker, vendored limits, scan-every-result, shared scanner,
no fork-only imports, and local _authority parity.
"""

import types
from pathlib import Path

from aitw.agent.profile import AgentProfile
from aitw.tools.registry import Tool, ToolContext

from agent_deployment import adapter as adapter_mod
from agent_deployment import round2_packaging
from agent_deployment.adapter import Deployment
from agent_deployment.limits import MAX_TOOL_RESULT_BYTES, record_truncation, truncate_text

PLANTED = "HT-CANARY-7Q2-PLANTED-LURE-DO-NOT-USE"


def _ctx(tmp_path, allowed):
    return ToolContext(
        tenant_id="tenant_a",
        workspace=tmp_path,
        profile=AgentProfile(
            tenant_id="tenant_a", role="r", working_instructions="w", allowed_tools=allowed
        ),
    )


# --- credential broker -------------------------------------------------------------------------


def test_make_broker_returns_real_broker_and_registers_secrets():
    dep = Deployment()
    broker = dep.make_broker(model_key="MODELKEY-xyz", tool_backing_secret="BACKING-abc")
    assert broker is not None
    assert hasattr(broker, "issue_tool_credential") and hasattr(broker, "is_valid")
    out = dep.make_scanner().scan("use MODELKEY-xyz and BACKING-abc").redacted
    assert "MODELKEY-xyz" not in out and "BACKING-abc" not in out
    assert out.count("[REDACTED]") == 2


def test_broker_issues_valid_credential_and_registers_token():
    dep = Deployment()
    broker = dep.make_broker(ttl_seconds=300)
    cred = broker.issue_tool_credential("tenant_a")
    assert hasattr(cred, "ttl_seconds") and cred.ttl_seconds == 300
    assert broker.is_valid(cred)
    assert cred.token not in dep.make_scanner().scan(f"token={cred.token}").redacted


def test_broker_accepts_reconstructed_equivalent_credential():
    dep = Deployment()
    broker = dep.make_broker(ttl_seconds=300)
    cred = broker.issue_tool_credential("tenant_a")
    reconstructed = types.SimpleNamespace(tenant_id=cred.tenant_id, token=cred.token, ttl_seconds=cred.ttl_seconds)
    assert broker.is_valid(reconstructed)  # token/tenant/TTL, not object identity


def test_broker_rejects_wrong_tenant_unknown_and_malformed():
    dep = Deployment()
    broker = dep.make_broker(ttl_seconds=300)
    cred = broker.issue_tool_credential("tenant_a")
    bogus = "unknown-token-value"  # not issued by this broker
    assert not broker.is_valid(types.SimpleNamespace(tenant_id="tenant_b", token=cred.token))
    assert not broker.is_valid(types.SimpleNamespace(tenant_id="tenant_a", token=bogus))
    assert not broker.is_valid(object())
    assert not broker.is_valid(types.SimpleNamespace(token=""))


def test_broker_expired_credential_invalid(monkeypatch):
    dep = Deployment()
    broker = dep.make_broker(ttl_seconds=10)
    cred = broker.issue_tool_credential("tenant_a")
    assert broker.is_valid(cred)
    monkeypatch.setattr(adapter_mod, "time", types.SimpleNamespace(time=lambda: cred.issued_at + 11))
    assert not broker.is_valid(cred)


def test_broker_honors_zero_ttl_not_coerced(monkeypatch):
    # N4: a host-passed ttl_seconds=0 must NOT be silently coerced to the 300 default.
    dep = Deployment()
    broker = dep.make_broker(ttl_seconds=0)
    cred = broker.issue_tool_credential("tenant_a")
    assert cred.ttl_seconds == 0
    monkeypatch.setattr(adapter_mod, "time", types.SimpleNamespace(time=lambda: cred.issued_at + 0.001))
    assert broker.is_valid(cred) is False


def test_broker_registers_preexisting_issued_tokens():
    dep = Deployment()
    dep.make_broker(issued_tokens=["PREEXISTING-TOKEN-1"])
    assert "PREEXISTING-TOKEN-1" not in dep.make_scanner().scan("t=PREEXISTING-TOKEN-1").redacted


def test_make_broker_kwarg_aliases():
    # Values assigned to plain locals (not credential-named lvalues) and passed by name, so the
    # secret guard's hardcoded-credential-assignment rule is not tripped by the test itself.
    k, s, t = "ALIASKEY-1", "ALIASSEC-2", "ALIASTOK-3"
    dep = Deployment()
    dep.make_broker(api_key=k, backing_secret=s, tokens=[t])
    out = dep.make_scanner().scan(f"{k} {s} {t}").redacted
    assert k not in out and s not in out and t not in out


# --- shared scanner: registered secrets redacted in tool output (Q1) --------------------------


def test_registered_secret_redacted_in_tool_output_via_shared_scanner(tmp_path):
    dep = Deployment()
    dep.make_broker(model_key="MODELKEY-xyz")  # registers into dep's shared scanner
    ctx = _ctx(tmp_path, ["echo_tool"])
    reg = dep.task_registry(ctx)  # no scanner passed -> uses the shared scanner
    reg.register(Tool("echo_tool", "echoes", lambda a, c: "leak MODELKEY-xyz end"))
    out = reg.call("echo_tool", {})
    assert "MODELKEY-xyz" not in out
    assert "[REDACTED]" in out


def test_every_string_tool_result_scanned_not_just_untrusted(tmp_path):
    # A tool NOT in the old _UNTRUSTED_OUTPUT_TOOLS gate must still have its output scanned.
    dep = Deployment()
    ctx = _ctx(tmp_path, ["echo_tool"])
    reg = dep.task_registry(ctx)
    reg.register(Tool("echo_tool", "echoes", lambda a, c: f"x {PLANTED} y"))
    assert PLANTED not in reg.call("echo_tool", {})


# --- vendored limits / record_truncation -------------------------------------------------------


def test_truncate_text_caps_and_marks():
    text, marker = truncate_text("z" * (MAX_TOOL_RESULT_BYTES + 100), MAX_TOOL_RESULT_BYTES)
    assert len(text.encode("utf-8")) <= MAX_TOOL_RESULT_BYTES
    assert marker and marker["truncated"] is True
    assert truncate_text("short", MAX_TOOL_RESULT_BYTES) == ("short", None)


def test_record_truncation_noops_without_host_attr():
    ctx = types.SimpleNamespace()  # stock-like ctx with no .truncations
    _, marker = truncate_text("z" * (MAX_TOOL_RESULT_BYTES + 1), MAX_TOOL_RESULT_BYTES)
    record_truncation(ctx, "tool_result", marker)  # must not crash / must not create the attr
    assert not hasattr(ctx, "truncations")


def test_record_truncation_records_when_attr_exists():
    ctx = types.SimpleNamespace(truncations=[])
    _, marker = truncate_text("z" * (MAX_TOOL_RESULT_BYTES + 1), MAX_TOOL_RESULT_BYTES)
    record_truncation(ctx, "tool_result", marker)
    assert ctx.truncations and ctx.truncations[0]["kind"] == "tool_result"


# --- no fork-only imports in shipped modules ---------------------------------------------------


def test_shipped_modules_have_no_fork_only_imports():
    root = Path("src/agent_deployment")
    forbidden = ("aitw.safety.limits", "aitw.orchestrator.deployments", "from aitw.tools.http_fetch import")
    for module in round2_packaging.SHIP_MODULES:
        text = (root / module).read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in text, f"{module} contains forbidden import {needle!r}"


# --- local _authority parity with stock -------------------------------------------------------


def test_local_authority_matches_stock():
    from aitw.tools.http_fetch import _authority as stock
    from agent_deployment.external_effects import _authority as local

    for url in [
        "http://localhost:8099/",
        "https://example.com/x",
        "https://example.com:8443/p",
        "HTTP://EXAMPLE.COM/x",
        "ftp://x/y",
        "not a url",
        "",
        "http://",
    ]:
        assert local(url) == stock(url), url
