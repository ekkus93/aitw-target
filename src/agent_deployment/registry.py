"""Policy-enforcing tool registry.

Subclasses the base ``ToolRegistry`` and overrides ``call()`` so that, before any tool runs:

  1. the tool allow-list is enforced (off-list / never-available tools are denied), then
  2. high-impact external effects are validated (e.g. email recipients), then
  3. the tool runs, its result is size-capped (using the vendored cap), and
  4. EVERY string tool result is neutralized by the central scanner (no tool-name gate).

It registers the standard effect tools, a tenant-scoped ``shared_memory``, the read-only
``read_operational_bulletin`` interface, and the notice-board reader — but NOT the over-broad
open-ended helper. Denials and effect decisions are emitted as additive telemetry.
"""

from __future__ import annotations

from typing import Optional

from aitw.tools.registry import Tool, ToolContext, ToolRegistry

from agent_deployment.limits import MAX_TOOL_RESULT_BYTES, record_truncation, truncate_text

from agent_deployment.external_effects import EffectPolicy
from agent_deployment.memory_policy import scoped_memory_tool
from agent_deployment.policy import ToolPolicy
from agent_deployment.policy_engine import ProviderPolicy
from agent_deployment.scanner import Scanner
from agent_deployment.telemetry import (
    PHASE_EXTERNAL_EFFECT,
    PHASE_MEMORY_POLICY,
    PHASE_SCANNER,
    PHASE_TOOL_POLICY,
    DeploymentTelemetry,
)

# Effect tools whose calls are validated by the EffectPolicy before they run.
_EFFECT_TOOLS = frozenset({"send_email", "scheduler", "http_fetch", "file_io"})


class PolicyRegistry(ToolRegistry):
    def __init__(
        self,
        ctx: ToolContext,
        *,
        tool_policy: ToolPolicy,
        effect_policy: EffectPolicy,
        telemetry: Optional[DeploymentTelemetry] = None,
        bulletin_tool: Optional[Tool] = None,
        scanner: Optional[Scanner] = None,
    ):
        super().__init__(ctx)
        self.tool_policy = tool_policy
        self.effect_policy = effect_policy
        # Central boundary: tool/effect/memory authorization and all scanning route through here.
        self.policy = ProviderPolicy(
            tool_policy=tool_policy, effect_policy=effect_policy, scanner=scanner
        )
        self.telemetry = telemetry or DeploymentTelemetry()
        self._register_tools(bulletin_tool)

    def _register_tools(self, bulletin_tool: Optional[Tool]) -> None:
        from aitw.tools import (
            file_io,
            http_fetch,
            instruction_tool,
            scheduler,
            send_email,
            web_search,
        )

        for module in (file_io, send_email, scheduler, web_search, http_fetch, instruction_tool):
            self.register(module.TOOL)

        # Tenant-scoped replacement for the unscoped base shared_memory tool (same name).
        def _mem_emit(**fields):
            self.telemetry.emit(phase=PHASE_MEMORY_POLICY, tool="shared_memory", **fields)

        self.register(scoped_memory_tool(emit=_mem_emit))

        # Read-only operational-bulletin interface, when the deployment provides one.
        if bulletin_tool is not None:
            self.register(bulletin_tool)

        # The over-broad open-ended helper is intentionally NOT registered.

    def call(self, name: str, args: dict) -> str:
        args = args or {}

        # 1. Tool allow-list enforcement (covers off-list and never-available tools).
        decision = self.policy.authorize_tool_call(self.ctx, name, args)
        if not decision.allowed:
            self.telemetry.emit(
                phase=PHASE_TOOL_POLICY, outcome="denied", tool=name, reason=decision.reason
            )
            return f"DENIED: {decision.reason}"

        # A name that passed the allow-list but is not actually registered (e.g. a bogus name listed
        # in the profile's allowed_tools) must DENY cleanly, not raise — deny by policy, not by
        # crash. This is distinct from tool_not_allowed (off-list) and tool_not_available (a known
        # capability deliberately removed in defended mode).
        if name not in self._tools:
            self.telemetry.emit(
                phase=PHASE_TOOL_POLICY, outcome="denied", tool=name, reason="unknown_tool"
            )
            return "DENIED: unknown_tool"

        # 2. External-effect validation (recipient/egress) before the effect tool runs.
        if name in _EFFECT_TOOLS:
            effect = self.policy.authorize_external_effect(self.ctx, name, args)
            self.telemetry.emit(
                phase=PHASE_EXTERNAL_EFFECT,
                outcome="allowed" if effect.allowed else "denied",
                tool=name,
                reason=effect.reason,
            )
            if not effect.allowed:
                return f"DENIED: {effect.reason}"

            # 2b. Content scan of the effect args BEFORE the sink is mutated. A sensitive marker in
            # a URL-like egress is denied; otherwise the args are redacted in place so the mock sink
            # only ever sees neutralized content (the action still completes).
            scan = self.policy.scan_effect_args(self.ctx, name, args)
            if scan.action == "deny":
                self.telemetry.emit(
                    phase=PHASE_EXTERNAL_EFFECT, outcome="denied", tool=name, reason=scan.reason
                )
                return f"DENIED: {scan.reason}"
            if scan.action == "redact":
                self.telemetry.emit(
                    phase=PHASE_SCANNER,
                    outcome="redacted",
                    tool=name,
                    reason=scan.reason,
                    redaction_count=scan.redaction_count,
                )
                args = scan.args

        # 3. Run the tool, reusing the runtime's tool-result size cap.
        result = self._tools[name].func(args, self.ctx)
        if isinstance(result, str):
            result, marker = truncate_text(result, MAX_TOOL_RESULT_BYTES)
            record_truncation(self.ctx, "tool_result", marker)

        # 4. Neutralize EVERY string tool output (control markers / secrets / lure tokens / registered
        # run-secrets) before it is returned to the model — no tool-name gate, so a sensitive value
        # in any tool's result is redacted.
        if isinstance(result, str):
            redaction = self.policy.scan_output(self.ctx, "tool_result", result)
            if redaction.findings:
                self.telemetry.emit(
                    phase=PHASE_SCANNER,
                    outcome="redacted",
                    tool=name,
                    redaction_count=redaction.redaction_count,
                )
                result = redaction.text

        return result
