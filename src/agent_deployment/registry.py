"""Policy-enforcing tool registry.

Subclasses the base ``ToolRegistry`` and overrides ``call()`` so that, before any tool runs:

  1. the tool allow-list is enforced (off-list / never-available tools are denied), then
  2. high-impact external effects are validated (e.g. email recipients), then
  3. the tool runs, its result is size-capped (reusing the runtime's cap), and
  4. untrusted tool output is neutralized by the central scanner.

It registers the standard effect tools, a tenant-scoped ``shared_memory``, the read-only
``read_operational_bulletin`` interface, and the notice-board reader — but NOT the over-broad
open-ended helper. Denials and effect decisions are emitted as additive telemetry.
"""

from __future__ import annotations

from typing import Optional

from aitw.safety.limits import MAX_TOOL_RESULT_BYTES, truncate_text
from aitw.tools.registry import Tool, ToolContext, ToolRegistry

from agent_deployment.external_effects import EffectPolicy
from agent_deployment.memory_policy import scoped_memory_tool
from agent_deployment.policy import ToolPolicy
from agent_deployment.scanner import redact_text
from agent_deployment.telemetry import (
    PHASE_EXTERNAL_EFFECT,
    PHASE_MEMORY_POLICY,
    PHASE_TOOL_POLICY,
    DeploymentTelemetry,
)

# Effect tools whose calls are validated by the EffectPolicy before they run.
_EFFECT_TOOLS = frozenset({"send_email", "scheduler", "http_fetch", "file_io"})

# Tools whose output is untrusted data and must be neutralized before returning to the model.
_UNTRUSTED_OUTPUT_TOOLS = frozenset({"shared_memory", "read_notice_board", "web_search"})


class PolicyRegistry(ToolRegistry):
    def __init__(
        self,
        ctx: ToolContext,
        *,
        tool_policy: ToolPolicy,
        effect_policy: EffectPolicy,
        telemetry: Optional[DeploymentTelemetry] = None,
        bulletin_tool: Optional[Tool] = None,
    ):
        super().__init__(ctx)
        self.tool_policy = tool_policy
        self.effect_policy = effect_policy
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
        decision = self.tool_policy.validate_tool_call(name, args, ctx=self.ctx)
        if not decision.allowed:
            self.telemetry.emit(
                phase=PHASE_TOOL_POLICY, outcome="denied", tool=name, reason=decision.reason
            )
            return f"DENIED: {decision.reason}"

        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")

        # 2. External-effect validation before the underlying effect tool runs.
        if name in _EFFECT_TOOLS:
            effect = self.effect_policy.validate_effect(name, args, ctx=self.ctx)
            self.telemetry.emit(
                phase=PHASE_EXTERNAL_EFFECT,
                outcome="allowed" if effect.allowed else "denied",
                tool=name,
                reason=effect.reason,
            )
            if not effect.allowed:
                return f"DENIED: {effect.reason}"

        # 3. Run the tool, reusing the runtime's tool-result size cap.
        result = self._tools[name].func(args, self.ctx)
        if isinstance(result, str):
            result, marker = truncate_text(result, MAX_TOOL_RESULT_BYTES)
            if marker:
                self.ctx.truncations.append({"kind": "tool_result", "tool": name, **marker})

        # 4. Neutralize untrusted tool output (control markers / secrets / lure tokens).
        if name in _UNTRUSTED_OUTPUT_TOOLS and isinstance(result, str):
            redaction = redact_text(result, surface="tool_result")
            if redaction.findings:
                self.telemetry.emit(
                    phase="context_sanitizer",
                    outcome="redacted",
                    tool=name,
                    redaction_count=redaction.redaction_count,
                )
                result = redaction.text

        return result
