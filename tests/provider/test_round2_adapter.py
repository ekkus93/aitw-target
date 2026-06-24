"""Round 2 intake adapter: DEPLOYMENT shape, ScopedStore isolation, and defended task_registry.

These exercise the adapter path the operator host actually drives (provider:DEPLOYMENT), independent
of the legacy RunHooks provider. The host V2Deployment base is absent in this fork, so the adapter
soft-imports it and falls back to ``object``; a sentinel base is injected via sys.modules to confirm
the adapter subclasses whatever base the host provides.
"""

import json
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
    import importlib

    # Re-import under the patched host module to confirm subclassing, then restore the ORIGINAL
    # module object so other tests keep the same class identities (the top-level imports in this
    # file are bound to it — a fresh re-import would break isinstance checks elsewhere).
    original = sys.modules.get("agent_deployment.adapter")
    sys.modules.pop("agent_deployment.adapter", None)
    try:
        reloaded = importlib.import_module("agent_deployment.adapter")
        assert issubclass(reloaded.Deployment, V2Deployment)
        assert reloaded.DEPLOYMENT.name == "defense"
    finally:
        if original is not None:
            sys.modules["agent_deployment.adapter"] = original
        else:
            sys.modules.pop("agent_deployment.adapter", None)


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


# --- host-scanner result normalization (#1) ---------------------------------------------------


def test_compose_scanner_normalizes_host_result_object():
    # A host redactor that returns a result OBJECT (with a .text attr) is normalized to its text,
    # and our scanner still runs as the net.
    class _HostObjResult:
        def redact_text(self, text, surface="unknown"):
            class _R:
                pass

            r = _R()
            r.text = text.replace("HOSTX", "[obj]")
            return r

    composed = _compose_scanner(scanner=_HostObjResult())
    out = composed.redact_text(f"a HOSTX and {PLANTED} b", surface="tool_result").text
    assert "HOSTX" not in out          # host result-object .text was applied
    assert PLANTED not in out          # our net still ran


def test_compose_scanner_normalizes_host_tuple_result():
    # A host redactor that returns a (text, meta) tuple is normalized to the first string element.
    class _HostTupleResult:
        def redact_text(self, text, surface="unknown"):
            return (text.replace("HOSTX", "[tup]"), ["meta"])

    composed = _compose_scanner(scanner=_HostTupleResult())
    out = composed.redact_text("HOSTX here", surface="tool_result").text
    assert out.startswith("[tup]")
    assert "HOSTX" not in out


def test_compose_scanner_unrecognized_host_return_falls_back_to_net():
    # An unrecognized host return (not str / .text / tuple) is NOT a failure: keep the input for the
    # pre-pass and let our scanner be the net. No scanner_error is forced.
    class _HostBadReturn:
        def redact_text(self, text, surface="unknown"):
            return 12345

    composed = _compose_scanner(scanner=_HostBadReturn())
    result = composed.redact_text(f"x {PLANTED} y", surface="tool_result")
    assert PLANTED not in result.text
    assert all(f.kind != "scanner_error" for f in result.findings)


# --- compose with a real Scanner instance (#3) ------------------------------------------------


def test_compose_scanner_carries_forward_real_scanner_config():
    from agent_deployment.adapter import _CompositeScanner

    sc = Scanner(extra_literals=frozenset({"MYSECRETLIT"}))
    composed = _compose_scanner(scanner=sc)  # real Scanner, no guard
    # Returns a plain Scanner carrying the configured literals (no host pre-pass -> not a composite).
    assert isinstance(composed, Scanner)
    assert not isinstance(composed, _CompositeScanner)
    assert "MYSECRETLIT" in composed.extra_literals
    assert "MYSECRETLIT" not in composed.redact_text("x MYSECRETLIT y", surface="tool_result").text


def test_compose_scanner_real_scanner_plus_guard_is_composite():
    from agent_deployment.adapter import _CompositeScanner

    sc = Scanner(extra_literals=frozenset({"MYSECRETLIT"}))

    class _Guard:
        def guard(self, text, surface="unknown"):
            return text.replace("GUARDX", "[g]")

    composed = _compose_scanner(scanner=sc, credential_guard=_Guard())
    assert isinstance(composed, _CompositeScanner)
    assert "MYSECRETLIT" in composed.extra_literals     # carried-forward config preserved
    out = composed.redact_text("MYSECRETLIT GUARDX", surface="tool_result").text
    assert "MYSECRETLIT" not in out                     # our net redacted the carried literal
    assert "GUARDX" not in out                          # guard pre-pass applied


# --- recipient fail-closed when fixtures unavailable (#4) -------------------------------------


def test_recipients_fail_closed_when_fixtures_raise(tmp_path, monkeypatch):
    import aitw.scenarios.fixtures as fixtures

    def _boom():
        raise OSError("fixtures unavailable")

    monkeypatch.setattr(fixtures, "load_tickets", _boom)
    ctx = _ctx(tmp_path, allowed=["send_email"])
    ctx.scenario_name = "support_triage"
    assert _allowed_recipients_for_ctx(ctx) == frozenset()      # fail closed to empty
    # The registry then denies even a plausible support address (deny-all when no allowlist).
    reg = DEPLOYMENT.task_registry(ctx)
    assert reg.call("send_email", {"to": "customer@acme.test", "body": "x"}).startswith("DENIED")
    assert ctx.sent_emails == []


# --- structured-payload scanner (recursive, fail-closed) --------------------------------------


def test_scan_dict_finds_nested_lure():
    sa = ScannerAdapter()
    assert sa.scan({"body": f"see {PLANTED}"})        # finding(s) present, not a silent []
    assert sa.check({"body": PLANTED}) is True


def test_redact_dict_redacts_value_preserves_keys():
    sa = ScannerAdapter()
    out = sa.redact({"body": f"x {PLANTED} y", "ok": "fine"})
    assert isinstance(out, dict) and set(out) == {"body", "ok"}
    assert PLANTED not in out["body"]
    assert out["ok"] == "fine"


def test_scan_and_redact_list_and_tuple():
    sa = ScannerAdapter()
    assert sa.scan(["safe", PLANTED])
    rl = sa.redact(["safe", PLANTED])
    assert isinstance(rl, list) and rl[0] == "safe" and PLANTED not in rl[1]
    rt = sa.redact(("safe", PLANTED))
    assert isinstance(rt, tuple) and PLANTED not in rt[1]


def test_scan_and_redact_set_and_frozenset():
    sa = ScannerAdapter()
    assert sa.scan({PLANTED})
    rs = sa.redact({PLANTED, "safe"})
    assert isinstance(rs, set) and all(PLANTED not in v for v in rs)
    rf = sa.redact(frozenset({PLANTED}))
    assert isinstance(rf, frozenset) and all(PLANTED not in v for v in rf)


def test_nested_structures_fully_redacted():
    sa = ScannerAdapter()
    payload = {"outer": [{"inner": PLANTED}, "safe"], "tags": ("t", PLANTED)}
    out = sa.redact(payload)
    assert PLANTED not in json.dumps(out)   # no raw lure survives anywhere in the structure
    assert sa.scan(payload)


def test_structured_injection_and_credential_detected():
    sa = ScannerAdapter()
    assert sa.scan({"a": "INJECT:: do bad things now"})
    cred = "sk-" + "ant-api03-" + "Z" * 24      # provider-key shape at runtime only
    assert sa.scan(["note", cred])
    assert cred not in sa.redact(["note", cred])[1]


def test_benign_structured_payload_no_findings_and_preserved():
    sa = ScannerAdapter()
    payload = {"greeting": "hello", "items": [1, 2, 3], "ok": True, "none": None}
    assert sa.scan(payload) == []
    assert sa.redact(payload) == payload


def test_scalars_preserved():
    sa = ScannerAdapter()
    assert sa.redact(5) == 5 and sa.redact(None) is None and sa.redact(True) is True
    assert sa.scan(12345) == [] and sa.scan(None) == []


def test_unknown_object_fails_closed():
    class _Weird:
        def __init__(self):
            self.secret = PLANTED

        def __str__(self):
            return self.secret

    sa = ScannerAdapter()
    obj = _Weird()
    assert sa.redact(obj) == "[redacted:unsupported_payload]"
    assert any(f.kind == "unsupported_payload" for f in sa.scan(obj))


def test_failing_scanner_on_structured_payload_fails_closed():
    sa = ScannerAdapter(_BoomScanner())
    out = sa.redact({"body": PLANTED, "nested": [PLANTED]})
    assert PLANTED not in json.dumps(out)                       # no raw nested string survives
    assert any(f.kind == "scanner_error" for f in sa.scan({"body": PLANTED}))
