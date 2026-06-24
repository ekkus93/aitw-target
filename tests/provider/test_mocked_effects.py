"""External effects stay mocked / sandboxed through the defended registry (TODO P2.6)."""

import pytest
from aitw.agent.profile import AgentProfile
from aitw.tools.registry import ToolContext

from agent_deployment.bulletin import bulletin_tool, default_bulletin
from agent_deployment.external_effects import EffectPolicy
from agent_deployment.policy import ToolPolicy
from agent_deployment.registry import PolicyRegistry
from agent_deployment.telemetry import DeploymentTelemetry


def _registry(tmp_path, allowed, *, recipients=frozenset(), egress=()):
    ctx = ToolContext(
        tenant_id="tenant_a",
        workspace=tmp_path,
        egress_allowlist=list(egress),
        profile=AgentProfile(
            tenant_id="tenant_a", role="r", working_instructions="w", allowed_tools=allowed
        ),
    )
    reg = PolicyRegistry(
        ctx,
        tool_policy=ToolPolicy(),
        effect_policy=EffectPolicy(allowed_recipients=frozenset(recipients)),
        telemetry=DeploymentTelemetry(),
        bulletin_tool=bulletin_tool(default_bulletin()),
    )
    return reg, ctx


def test_send_email_only_mutates_mock_sink(tmp_path):
    reg, ctx = _registry(tmp_path, ["send_email"], recipients={"customer@acme.test"})
    out = reg.call("send_email", {"to": "customer@acme.test", "subject": "s", "body": "b"})
    assert out.startswith("MOCK-EMAIL")           # mock transport, no real delivery
    assert ctx.sent_emails == [{"to": "customer@acme.test", "subject": "s", "body": "b"}]


def test_scheduler_only_mutates_mock_sink(tmp_path):
    reg, ctx = _registry(tmp_path, ["scheduler"])
    out = reg.call("scheduler", {"when": "2026-01-01", "title": "review"})
    assert out.startswith("MOCK-SCHEDULED")
    assert ctx.scheduled == [{"when": "2026-01-01", "title": "review"}]


def test_http_fetch_never_reaches_non_allowlisted_host(tmp_path):
    reg, ctx = _registry(tmp_path, ["http_fetch"], egress=["http://localhost:8099/"])
    assert reg.call("http_fetch", {"url": "https://example.com/"}).startswith("DENIED")
    assert ctx.fetched == []                       # no socket, no record


def test_file_write_confined_to_workspace(tmp_path):
    reg, ctx = _registry(tmp_path, ["file_io"])
    # A normal write stays in the workspace.
    reg.call("file_io", {"op": "write", "path": "note.txt", "content": "hi"})
    assert (tmp_path / "note.txt").read_text() == "hi"
    assert ctx.file_writes and ctx.file_writes[0]["path"] == "note.txt"
    # A traversal attempt is refused by workspace containment.
    with pytest.raises(ValueError):
        reg.call("file_io", {"op": "write", "path": "../escape.txt", "content": "x"})
    assert not (tmp_path.parent / "escape.txt").exists()
