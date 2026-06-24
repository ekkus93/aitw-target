"""The deployment entrypoint: wires the policy layer into the runtime's hook seams.

``AgentDeployment`` owns the per-run policy state (tool allow-list, external-effect rules, the
validated operational bulletin and its derived posture) and exposes the three hook callables the
runtime's ``run()`` accepts. Constructing it and passing ``deployment.hooks()`` to ``run()`` is the
whole integration — no fork of the run loop, and all existing scoring/telemetry is reused.
"""

from __future__ import annotations

from typing import Mapping, Optional

from aitw.orchestrator.run_harness import RunHooks
from aitw.tools.registry import ToolContext

from agent_deployment.bulletin import bulletin_tool, derive_posture, load_bulletin
from agent_deployment.external_effects import EffectPolicy
from agent_deployment.policy import ToolPolicy
from agent_deployment.registry import PolicyRegistry
from agent_deployment.sanitizer import sanitize_model_context
from agent_deployment.telemetry import (
    PHASE_CONTEXT_SANITIZER,
    PHASE_OPERATIONAL_BULLETIN,
    DeploymentTelemetry,
)


def _allowed_recipients_for(scenario_name: str) -> frozenset:
    """Derive the safe-recipient set from the SAME scenario fixtures the success metric uses.

    Only the support-triage task legitimately sends email; its recipients are the seeded ticket
    ``from`` addresses. Other scenarios do not grant ``send_email`` (so the effect policy never
    gates email for them, and would fail closed if one tried).
    """
    if scenario_name == "support_triage":
        from aitw.scenarios.fixtures import load_tickets

        return frozenset(t["from"] for t in load_tickets())
    return frozenset()


class AgentDeployment:
    def __init__(
        self,
        *,
        allowed_recipients: frozenset = frozenset(),
        bulletin: Optional[dict] = None,
        env: Optional[Mapping[str, str]] = None,
    ):
        self.tool_policy = ToolPolicy()
        self.effect_policy = EffectPolicy(allowed_recipients=frozenset(allowed_recipients))
        # Validated once and held stable for the whole run (repeated reads return the same object).
        self.bulletin = bulletin if bulletin is not None else load_bulletin(env=env)
        self.posture = derive_posture(self.bulletin)
        self._telemetry: Optional[DeploymentTelemetry] = None

    @classmethod
    def for_scenario(
        cls,
        scenario_name: str,
        *,
        bulletin: Optional[dict] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> "AgentDeployment":
        return cls(
            allowed_recipients=_allowed_recipients_for(scenario_name),
            bulletin=bulletin,
            env=env,
        )

    # --- RunHooks seams ----------------------------------------------------------------------

    def build_registry(self, ctx: ToolContext, log, tags) -> PolicyRegistry:
        self._telemetry = DeploymentTelemetry(log=log, tags=tags)
        return PolicyRegistry(
            ctx,
            tool_policy=self.tool_policy,
            effect_policy=self.effect_policy,
            telemetry=self._telemetry,
            bulletin_tool=bulletin_tool(self.bulletin),
        )

    def pre_task(self, ctx: ToolContext, registry, log, tags) -> None:
        """Stable pre-task phase: the bulletin is already validated; record neutral telemetry once."""
        telemetry = self._telemetry or DeploymentTelemetry(log=log, tags=tags)
        telemetry.emit(
            phase=PHASE_OPERATIONAL_BULLETIN,
            outcome="processed",
            tool=None,
            bulletin_id=self.bulletin["bulletin_id"],
            priority=self.posture["priority"],
            posture_profile=self.posture["posture_profile"],
        )

    def sanitize_context(self, blob: str, ctx: ToolContext) -> str:
        result = sanitize_model_context(blob, source="shared_memory", tenant_id=ctx.tenant_id)
        if result.findings and self._telemetry is not None:
            self._telemetry.emit(
                phase=PHASE_CONTEXT_SANITIZER,
                outcome="redacted",
                tool=None,
                redaction_count=result.redaction_count,
            )
        return result.text

    def hooks(self) -> RunHooks:
        return RunHooks(
            build_registry=self.build_registry,
            pre_task=self.pre_task,
            sanitize_context=self.sanitize_context,
        )
