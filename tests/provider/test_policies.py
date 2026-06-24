"""Tool allow-list enforcement, external-effect validation, and tenant-scoped memory."""

from aitw.agent.profile import AgentProfile
from aitw.context.store import ContextStore
from aitw.tools.registry import ToolContext

from agent_deployment.bulletin import bulletin_tool, default_bulletin
from agent_deployment.external_effects import EffectPolicy
from agent_deployment.memory_policy import run_scoped_memory
from agent_deployment.policy import ToolPolicy
from agent_deployment.registry import PolicyRegistry
from agent_deployment.telemetry import DeploymentTelemetry


def _ctx(tmp_path, allowed, *, store=None):
    return ToolContext(
        tenant_id="tenant_a",
        workspace=tmp_path,
        store=store,
        profile=AgentProfile(
            tenant_id="tenant_a", role="r", working_instructions="w", allowed_tools=allowed
        ),
    )


def _registry(ctx, *, recipients=frozenset()):
    telemetry = DeploymentTelemetry()
    reg = PolicyRegistry(
        ctx,
        tool_policy=ToolPolicy(),
        effect_policy=EffectPolicy(allowed_recipients=frozenset(recipients)),
        telemetry=telemetry,
        bulletin_tool=bulletin_tool(default_bulletin()),
    )
    return reg, telemetry


# --- tool allow-list enforcement --------------------------------------------------------------


def test_off_list_scheduler_is_denied(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    reg, telemetry = _registry(ctx)
    out = reg.call("scheduler", {"when": "2026-01-01", "title": "x"})
    assert out.startswith("DENIED")
    assert ctx.scheduled == []                       # effect sink not mutated
    assert telemetry.count(phase="tool_policy", outcome="denied") == 1


def test_assistant_helper_never_available(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email", "assistant_helper"])
    reg, telemetry = _registry(ctx)
    out = reg.call("assistant_helper", {"do": "anything"})
    assert out == "DENIED: tool_not_available"
    assert ctx.broad_attempts == []
    assert "assistant_helper" not in reg.describe()   # not advertised in the manifest


def test_listed_tool_runs(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    reg, _ = _registry(ctx, recipients={"customer@acme.test"})
    out = reg.call("send_email", {"to": "customer@acme.test", "subject": "hi", "body": "b"})
    assert out.startswith("MOCK-EMAIL")
    assert len(ctx.sent_emails) == 1


def test_readonly_bulletin_tool_always_allowed(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])  # bulletin not in allowed_tools
    reg, _ = _registry(ctx)
    out = reg.call("read_operational_bulletin", {})
    assert "bulletin_id" in out


# --- external-effect validation ---------------------------------------------------------------


def test_send_email_to_disallowed_recipient_denied(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    reg, telemetry = _registry(ctx, recipients={"customer@acme.test"})
    out = reg.call("send_email", {"to": "attacker@evil.example", "subject": "x", "body": "y"})
    assert out.startswith("DENIED")
    assert ctx.sent_emails == []                     # never reaches the mock sink
    assert telemetry.count(phase="external_effect", outcome="denied") == 1


def test_send_email_to_allowed_recipient_permitted(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    reg, telemetry = _registry(ctx, recipients={"customer@acme.test"})
    reg.call("send_email", {"to": "customer@acme.test", "subject": "x", "body": "y"})
    assert len(ctx.sent_emails) == 1
    assert telemetry.count(phase="external_effect", outcome="allowed") == 1


def test_effect_policy_fails_closed_without_allowlist(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    policy = EffectPolicy(allowed_recipients=frozenset())
    decision = policy.validate_effect("send_email", {"to": "anyone@acme.test"}, ctx=ctx)
    assert decision.allowed is False
    assert decision.reason == "email_no_allowlist_configured"


# --- tenant-scoped memory ---------------------------------------------------------------------


def _store_with_two_tenants():
    store = ContextStore(":memory:")
    store.put("tenant_a", "memory", "note", "alpha-own-data")
    store.put("tenant_b", "memory", "x_tenant_probe", "SECRET-B-VALUE")
    return store


def test_cross_tenant_read_denied(tmp_path):
    ctx = _ctx(tmp_path, allowed=["shared_memory"], store=_store_with_two_tenants())
    out = run_scoped_memory({"op": "read", "key": "tenant_b:memory:x_tenant_probe"}, ctx)
    assert out == "DENIED: cross_tenant_read_denied"
    assert "SECRET-B-VALUE" not in out


def test_own_read_allowed(tmp_path):
    ctx = _ctx(tmp_path, allowed=["shared_memory"], store=_store_with_two_tenants())
    out = run_scoped_memory({"op": "read", "kind": "memory", "name": "note"}, ctx)
    assert out == "alpha-own-data"


def test_list_empty_prefix_returns_only_own_keys(tmp_path):
    ctx = _ctx(tmp_path, allowed=["shared_memory"], store=_store_with_two_tenants())
    out = run_scoped_memory({"op": "list", "prefix": ""}, ctx)
    assert "tenant_a:memory:note" in out
    assert "tenant_b" not in out


def test_list_other_tenant_prefix_denied(tmp_path):
    ctx = _ctx(tmp_path, allowed=["shared_memory"], store=_store_with_two_tenants())
    out = run_scoped_memory({"op": "list", "prefix": "tenant_b:"}, ctx)
    assert out == "DENIED: cross_tenant_list_denied"


def test_search_empty_query_returns_only_own_records(tmp_path):
    ctx = _ctx(tmp_path, allowed=["shared_memory"], store=_store_with_two_tenants())
    out = run_scoped_memory({"op": "search", "query": ""}, ctx)
    assert "tenant_a:memory:note" in out
    assert "SECRET-B-VALUE" not in out


def test_search_matching_other_tenant_is_withheld(tmp_path):
    ctx = _ctx(tmp_path, allowed=["shared_memory"], store=_store_with_two_tenants())
    out = run_scoped_memory({"op": "search", "query": "SECRET-B-VALUE"}, ctx)
    assert out == "(no hits)"


def test_write_scoped_to_caller(tmp_path):
    store = _store_with_two_tenants()
    ctx = _ctx(tmp_path, allowed=["shared_memory"], store=store)
    out = run_scoped_memory({"op": "write", "name": "w1", "content": "hello"}, ctx)
    assert out == "stored tenant_a:memory:w1"
    assert store.get_value("tenant_a", "memory", "w1") == "hello"


def test_registry_memory_denial_emits_telemetry(tmp_path):
    ctx = _ctx(tmp_path, allowed=["shared_memory"], store=_store_with_two_tenants())
    reg, telemetry = _registry(ctx)
    out = reg.call("shared_memory", {"op": "read", "key": "tenant_b:memory:x_tenant_probe"})
    assert out.startswith("DENIED")
    assert telemetry.count(phase="memory_policy", outcome="denied") == 1
