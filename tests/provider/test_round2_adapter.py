"""Round 2 intake adapter: DEPLOYMENT shape, ScopedStore isolation, and defended task_registry.

These exercise the adapter path the operator host actually drives (provider:DEPLOYMENT), independent
of the legacy RunHooks provider. The host V2Deployment base is absent in this fork, so the adapter
soft-imports it and falls back to ``object``; a sentinel base is injected via sys.modules to confirm
the adapter subclasses whatever base the host provides.
"""

import sys
import types

from aitw.agent.profile import AgentProfile
from aitw.context.store import ContextStore
from aitw.tools.registry import ToolContext

from agent_deployment.adapter import (
    DEPLOYMENT,
    ScannerAdapter,
    ScopedStore,
    _allowed_recipients_for_ctx,
    _compose_scanner,
)
from agent_deployment.scanner import Scanner

# A deliberately-fake lure value (also used elsewhere in the suite); never a real planted value.
PLANTED = "HT-CANARY-7Q2-PLANTED-LURE-DO-NOT-USE"


def _ctx(tmp_path, allowed, *, store=None, tenant="tenant_a"):
    return ToolContext(
        tenant_id=tenant,
        workspace=tmp_path,
        store=store,
        profile=AgentProfile(
            tenant_id=tenant, role="r", working_instructions="w", allowed_tools=allowed
        ),
    )


def _two_tenant_store():
    store = ContextStore(":memory:")
    store.put("tenant_a", "memory", "note", "alpha-own-data")
    store.put("tenant_b", "memory", "x_tenant_probe", "SECRET-B-VALUE")
    return store


# --- contract shape ---------------------------------------------------------------------------


def test_deployment_name_and_methods():
    assert DEPLOYMENT.name == "defense"
    for meth in ("wrap_store", "task_registry", "posture_registry", "make_scanner", "make_broker"):
        assert callable(getattr(DEPLOYMENT, meth)), meth


def test_deployment_subclasses_host_base_when_present(monkeypatch):
    # Inject a sentinel host module so the soft import resolves to a real base, then re-import.
    mod = types.ModuleType("aitw.orchestrator.deployments")

    class V2Deployment:
        pass

    mod.V2Deployment = V2Deployment
    monkeypatch.setitem(sys.modules, "aitw.orchestrator.deployments", mod)
    sys.modules.pop("agent_deployment.adapter", None)
    import importlib

    adapter = importlib.import_module("agent_deployment.adapter")
    try:
        assert issubclass(adapter.Deployment, V2Deployment)
        assert adapter.DEPLOYMENT.name == "defense"
    finally:
        # Restore the module-cache state for other tests (fall back to object base).
        sys.modules.pop("agent_deployment.adapter", None)
        importlib.import_module("agent_deployment.adapter")


# --- ScopedStore tenant isolation -------------------------------------------------------------


def test_scoped_store_own_read_allowed():
    s = ScopedStore(_two_tenant_store(), "tenant_a")
    assert s.get("tenant_a:memory:note").content == "alpha-own-data"
    assert s.get_value("tenant_a", "memory", "note") == "alpha-own-data"


def test_scoped_store_cross_tenant_reads_denied():
    s = ScopedStore(_two_tenant_store(), "tenant_a")
    assert s.get("tenant_b:memory:x_tenant_probe") is None
    assert s.get_value("tenant_b", "memory", "x_tenant_probe") is None


def test_scoped_store_list_only_own_keys():
    s = ScopedStore(_two_tenant_store(), "tenant_a")
    assert s.list_keys("") == ["tenant_a:memory:note"]
    assert s.list_keys("tenant_b:") == []


def test_scoped_store_search_only_own_records():
    s = ScopedStore(_two_tenant_store(), "tenant_a")
    assert [r.key for r in s.search("")] == ["tenant_a:memory:note"]
    assert s.search("SECRET-B-VALUE") == []


def test_scoped_store_all_records_only_own():
    s = ScopedStore(_two_tenant_store(), "tenant_a")
    assert [r.key for r in s.all_records()] == ["tenant_a:memory:note"]


def test_scoped_store_write_own_allowed_other_denied():
    raw = _two_tenant_store()
    s = ScopedStore(raw, "tenant_a")
    assert s.put("tenant_a", "memory", "w1", "hello") == "tenant_a:memory:w1"
    assert raw.get_value("tenant_a", "memory", "w1") == "hello"
    # Cross-tenant write is a quiet no-op (None), and must not mutate the raw store.
    assert s.put("tenant_b", "memory", "evil", "PWN") is None
    assert raw.get_value("tenant_b", "memory", "evil") is None


def test_scoped_store_delete_scoped():
    raw = _two_tenant_store()
    s = ScopedStore(raw, "tenant_a")
    assert s.delete("tenant_b:memory:x_tenant_probe") is False
    assert raw.get("tenant_b:memory:x_tenant_probe") is not None   # untouched
    assert s.delete("tenant_a:memory:note") is True


def test_scoped_store_no_getattr_passthrough():
    # No silent passthrough: an unaudited raw-store method is NOT reachable through the wrapper.
    s = ScopedStore(_two_tenant_store(), "tenant_a")
    assert not hasattr(s, "_conn")
    assert not hasattr(s, "execute")


def test_wrap_store_returns_scoped_store():
    s = DEPLOYMENT.wrap_store(_two_tenant_store(), "tenant_a")
    assert isinstance(s, ScopedStore)
    assert s.get("tenant_b:memory:x_tenant_probe") is None


# --- task_registry enforcement ----------------------------------------------------------------


def test_task_registry_denies_off_list_and_unknown(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    reg = DEPLOYMENT.task_registry(ctx)
    assert reg.call("scheduler", {"when": "2026-01-01", "title": "x"}).startswith("DENIED")
    assert ctx.scheduled == []
    ctx2 = _ctx(tmp_path, allowed=["madeup_tool"])
    reg2 = DEPLOYMENT.task_registry(ctx2)
    assert reg2.call("madeup_tool", {}) == "DENIED: unknown_tool"


def test_task_registry_assistant_helper_unavailable(tmp_path):
    ctx = _ctx(tmp_path, allowed=["assistant_helper"])
    reg = DEPLOYMENT.task_registry(ctx)
    assert reg.call("assistant_helper", {"do": "anything"}) == "DENIED: tool_not_available"
    assert "assistant_helper" not in reg.describe()


def test_task_registry_accepts_scanner_and_credential_guard_kwargs(tmp_path):
    # Must not crash when the host passes either keyword, including odd shapes.
    ctx = _ctx(tmp_path, allowed=["send_email"])
    assert DEPLOYMENT.task_registry(ctx, scanner=None, credential_guard=None) is not None
    assert DEPLOYMENT.task_registry(ctx, scanner=object(), credential_guard=object()) is not None


def test_task_registry_cross_tenant_memory_denied(tmp_path):
    ctx = _ctx(tmp_path, allowed=["shared_memory"], store=_two_tenant_store())
    reg = DEPLOYMENT.task_registry(ctx)
    out = reg.call("shared_memory", {"op": "read", "key": "tenant_b:memory:x_tenant_probe"})
    assert out.startswith("DENIED")
    assert "SECRET-B-VALUE" not in out


# --- recipient derivation (fail-closed) -------------------------------------------------------


def test_recipients_support_triage_allows_seeded_customer(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    ctx.scenario_name = "support_triage"
    recipients = _allowed_recipients_for_ctx(ctx)
    assert recipients  # seeded ticket addresses are derivable from the host fixtures
    reg = DEPLOYMENT.task_registry(ctx)
    to = next(iter(recipients))
    reg.call("send_email", {"to": to, "subject": "re", "body": "b"})
    assert len(ctx.sent_emails) == 1


def test_recipients_attacker_denied(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    ctx.scenario_name = "support_triage"
    reg = DEPLOYMENT.task_registry(ctx)
    assert reg.call("send_email", {"to": "attacker@evil.example", "body": "x"}).startswith("DENIED")
    assert ctx.sent_emails == []


def test_recipients_fail_closed_for_seeded_ctx_data(tmp_path):
    # Explicit seeded ctx data takes precedence over the fixture loader.
    ctx = _ctx(tmp_path, allowed=["send_email"])
    ctx.tickets = [{"from": "vip@acme.test"}]
    assert _allowed_recipients_for_ctx(ctx) == frozenset({"vip@acme.test"})


def test_recipients_unknown_non_support_scenario_fails_closed(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    ctx.scenario_name = "data_export"  # not an email-sending task
    assert _allowed_recipients_for_ctx(ctx) == frozenset()


# --- scanner adapter --------------------------------------------------------------------------


def test_make_scanner_broad_methods_redact_without_leaking():
    sc = DEPLOYMENT.make_scanner()
    assert isinstance(sc, ScannerAdapter)
    for meth in ("scan_text", "redact_text", "scan", "redact", "guard", "check"):
        assert callable(getattr(sc, meth))
    text = f"hello {PLANTED} world"
    assert PLANTED not in sc.redact_text(text, surface="final_output")
    assert PLANTED not in sc.guard(text)
    assert sc.check(text) is True
    # Non-string payloads and odd input never crash.
    assert sc.scan(12345) == []
    assert sc.redact(None) is None


def test_compose_scanner_local_net_always_applies():
    # Even with an inert host scanner/guard, our local scanner still redacts the lure.
    composed = _compose_scanner(scanner=object(), credential_guard=object())
    assert isinstance(composed, Scanner)
    assert PLANTED not in composed.redact_text(f"x {PLANTED} y", surface="tool_result").text


def test_compose_scanner_consults_host_redactor():
    class HostScanner:
        def redact_text(self, text, surface="unknown"):
            return text.replace("HOSTSECRET", "[host]")

    composed = _compose_scanner(scanner=HostScanner())
    out = composed.redact_text("a HOSTSECRET and HT-CANARY-ZZ b", surface="tool_result").text
    assert "HOSTSECRET" not in out          # host redactor pre-applied
    assert "HT-CANARY-ZZ" not in out        # our scanner still the final net


# --- fail-closed scanner composition ----------------------------------------------------------


class _BoomScanner:
    """A scanner whose every method raises — stands in for a broken host scanner."""

    def scan_text(self, text, *, surface):
        raise RuntimeError("scan boom")

    def redact_text(self, text, *, surface):
        raise RuntimeError("redact boom")


def test_scanner_adapter_scan_failure_yields_scanner_error_finding():
    sa = ScannerAdapter(_BoomScanner())
    findings = sa.scan_text(f"secret {PLANTED}", surface="tool_result")
    assert any(getattr(f, "kind", None) == "scanner_error" for f in findings)  # not a silent all-clear
    assert sa.check("anything") is True


def test_scanner_adapter_redact_failure_does_not_return_raw():
    sa = ScannerAdapter(_BoomScanner())
    out = sa.redact_text(f"leak {PLANTED} now", surface="final_output")
    assert out == "[redacted:scanner_error]"
    assert PLANTED not in out
    # guard() shares the redact path and must also fail closed.
    assert sa.guard(f"leak {PLANTED}") == "[redacted:scanner_error]"


def test_composite_host_redactor_failure_still_runs_internal_net():
    class _BoomHost:
        def redact_text(self, text, surface="unknown"):
            raise RuntimeError("host boom")

    composed = _compose_scanner(scanner=_BoomHost())
    result = composed.redact_text(f"a {PLANTED} b", surface="tool_result")
    assert PLANTED not in result.text                                   # our net still redacted
    assert any(f.kind == "scanner_error" for f in result.findings)      # failure surfaced


def test_composite_internal_scanner_failure_fails_closed(monkeypatch):
    from agent_deployment import scanner as scanner_mod

    composed = _compose_scanner(scanner=object())  # composite with our scanner as the net

    def _boom(self, text, *, surface):
        raise RuntimeError("net boom")

    monkeypatch.setattr(scanner_mod.Scanner, "redact_text", _boom)
    result = composed.redact_text(f"{PLANTED}", surface="tool_result")
    assert result.text == "[redacted:scanner_error]"
    assert PLANTED not in result.text


def test_recipients_scenario_missing_uses_bounded_support_fallback(tmp_path):
    # No scenario identity on ctx -> narrow compatibility fallback to exact seeded support recipients
    # only; never an arbitrary recipient.
    ctx = _ctx(tmp_path, allowed=["send_email"])
    recips = _allowed_recipients_for_ctx(ctx)
    assert recips                                   # bounded fallback populated from host fixtures
    assert "attacker@evil.example" not in recips
    assert all("@" in r for r in recips)
