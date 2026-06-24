"""Extended external-effect policies: http_fetch egress validation + metadata."""

from aitw.agent.profile import AgentProfile
from aitw.tools.registry import ToolContext

from agent_deployment.bulletin import bulletin_tool, default_bulletin
from agent_deployment.external_effects import EffectPolicy
from agent_deployment.policy import ToolPolicy
from agent_deployment.registry import PolicyRegistry
from agent_deployment.telemetry import DeploymentTelemetry

ALLOWLIST = ["http://localhost:8099/"]


def _ctx(tmp_path, allowed, egress):
    return ToolContext(
        tenant_id="tenant_a",
        workspace=tmp_path,
        egress_allowlist=list(egress),
        profile=AgentProfile(
            tenant_id="tenant_a", role="r", working_instructions="w", allowed_tools=allowed
        ),
    )


def _registry(ctx):
    telemetry = DeploymentTelemetry()
    reg = PolicyRegistry(
        ctx,
        tool_policy=ToolPolicy(),
        effect_policy=EffectPolicy(),
        telemetry=telemetry,
        bulletin_tool=bulletin_tool(default_bulletin()),
    )
    return reg, telemetry


def test_http_fetch_allowlisted_url_permitted(tmp_path):
    ctx = _ctx(tmp_path, allowed=["http_fetch"], egress=ALLOWLIST)
    reg, telemetry = _registry(ctx)
    out = reg.call("http_fetch", {"url": "http://localhost:8099/data"})
    assert out.startswith("MOCK 200")
    assert ctx.fetched and ctx.fetched[0]["url"] == "http://localhost:8099/data"
    assert telemetry.count(phase="external_effect", outcome="allowed") == 1


def test_http_fetch_non_allowlisted_url_denied(tmp_path):
    ctx = _ctx(tmp_path, allowed=["http_fetch"], egress=ALLOWLIST)
    reg, telemetry = _registry(ctx)
    out = reg.call("http_fetch", {"url": "http://evil.example/exfil"})
    assert out.startswith("DENIED")
    assert ctx.fetched == []                       # never reached the mock sink
    assert telemetry.count(phase="external_effect", outcome="denied") == 1


def test_http_fetch_unparseable_url_denied(tmp_path):
    ctx = _ctx(tmp_path, allowed=["http_fetch"], egress=ALLOWLIST)
    reg, _ = _registry(ctx)
    assert reg.call("http_fetch", {"url": "not a url"}).startswith("DENIED")


def test_effect_policy_email_unaffected_by_http_branch(tmp_path):
    # The added http_fetch branch must not change email behavior.
    ctx = _ctx(tmp_path, allowed=["send_email"], egress=ALLOWLIST)
    policy = EffectPolicy(allowed_recipients=frozenset({"customer@acme.test"}))
    assert policy.validate_effect("send_email", {"to": "customer@acme.test"}, ctx=ctx).allowed
    assert not policy.validate_effect("send_email", {"to": "x@evil.example"}, ctx=ctx).allowed


def test_send_email_missing_recipient_denied(tmp_path):
    # An empty or whitespace-only recipient is denied as email_missing_recipient, before any sink.
    ctx = _ctx(tmp_path, allowed=["send_email"], egress=ALLOWLIST)
    policy = EffectPolicy(allowed_recipients=frozenset({"customer@acme.test"}))
    d = policy.validate_effect("send_email", {"to": "", "body": "x"}, ctx=ctx)
    assert d.allowed is False and d.reason == "email_missing_recipient"
    assert policy.validate_effect("send_email", {"to": "   "}, ctx=ctx).reason == "email_missing_recipient"
