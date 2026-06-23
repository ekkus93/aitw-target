"""Tool policy + prompt manifest tests (AITW_TARGET_HARDENING P1.1, P1.2).

Decision: allowed_tools is ADVISORY (Option A) — the registry does NOT enforce it. The prompt
carries a manifest of the actually-registered tools, distinct from the profile advisory list.
"""

import json

from aitw.agent.profile import AgentProfile
from aitw.orchestrator.run_harness import run
from aitw.tools.registry import Tool, ToolContext, ToolRegistry, default_registry
from test_run_harness import make_scenario


def _ctx(tmp_path, allowed):
    return ToolContext(
        tenant_id="t",
        workspace=tmp_path,
        profile=AgentProfile(tenant_id="t", role="r", working_instructions="w", allowed_tools=allowed),
    )


# --- P1.1: advisory, not enforced --------------------------------------------------------------


def test_registry_calls_tool_not_in_advisory_list(tmp_path):
    ctx = _ctx(tmp_path, allowed=["listed"])
    reg = ToolRegistry(ctx)
    reg.register(Tool("listed", "d", lambda a, c: "ok"))
    reg.register(Tool("unlisted", "d", lambda a, c: "ok"))
    # A registered tool is callable even though it is not in allowed_tools (not an enforcement
    # boundary). This preserves the deliberately broad tool surface.
    assert reg.call("unlisted", {}) == "ok"


def test_outside_advisory_call_is_recorded(tmp_path):
    ctx = _ctx(tmp_path, allowed=["listed"])
    reg = ToolRegistry(ctx)
    reg.register(Tool("listed", "d", lambda a, c: "ok"))
    reg.register(Tool("unlisted", "d", lambda a, c: "ok"))
    reg.call("unlisted", {})
    reg.call("listed", {})
    assert ctx.outside_advisory_calls == ["unlisted"]  # only the off-list call is flagged


def test_default_registry_exceeds_any_single_advisory_list(tmp_path):
    # The callable surface is intentionally broader than what any scenario profile advertises.
    ctx = _ctx(tmp_path, allowed=["send_email"])
    reg = default_registry(ctx)
    assert set(reg.names()) - {"send_email"}, "registry should expose tools beyond the advisory list"


# --- P1.2: prompt carries the tool manifest ----------------------------------------------------


def test_system_prompt_includes_manifest_distinct_from_advisory(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    reg = default_registry(ctx)
    prompt = ctx.profile.system_prompt(tool_manifest=reg.describe())
    assert "Profile advisory tools" in prompt
    assert "Registered tools" in prompt
    for name in reg.names():
        assert name in prompt, f"registered tool {name!r} missing from manifest"


def test_system_prompt_without_manifest_omits_registered_section(tmp_path):
    ctx = _ctx(tmp_path, allowed=["send_email"])
    prompt = ctx.profile.system_prompt()
    assert "Registered tools" not in prompt
    assert "Profile advisory tools" in prompt


def test_run_passes_manifest_prompt_to_adapter(tmp_path, monkeypatch):
    import aitw.orchestrator.run_harness as rh

    captured = {}

    class RecordingAdapter:
        def complete(self, system, messages):
            captured["system"] = system
            return json.dumps({"thought": "done", "final": "ok"})

    monkeypatch.setattr(rh, "_build_adapter", lambda mc, sc: RecordingAdapter())
    run(make_scenario(), attack_fixture=None, runs_dir=tmp_path, run_id="manifest")
    assert "Registered tools" in captured["system"]
    assert "send_email" in captured["system"]
