"""The deployment entrypoint: wires the policy layer into the runtime's hook seams.

``AgentDeployment`` owns the per-run policy state (tool allow-list, external-effect rules, the
validated operational bulletin and its derived posture) and exposes the three hook callables the
runtime's ``run()`` accepts. Constructing it and passing ``deployment.hooks()`` to ``run()`` is the
whole integration — no fork of the run loop, and all existing scoring/telemetry is reused.
"""

from __future__ import annotations

import re
from typing import Mapping, Optional

from aitw.orchestrator.run_harness import RunHooks
from aitw.tools.registry import ToolContext

from agent_deployment.bulletin import bulletin_tool, derive_posture, load_bulletin, validate_bulletin
from agent_deployment.external_effects import EffectPolicy
from agent_deployment.policy import ToolPolicy
from agent_deployment.registry import PolicyRegistry
from agent_deployment.sanitizer import sanitize_model_context
from agent_deployment.scanner import Scanner, load_pattern_file
from agent_deployment.telemetry import (
    PHASE_CONTEXT_SANITIZER,
    PHASE_FINAL_OUTPUT,
    PHASE_OPERATIONAL_BULLETIN,
    PHASE_SCANNER,
    DeploymentTelemetry,
    RedactingObservationLog,
)

# Neutral env var pointing at an optional private redaction-pattern file (one regex per line, or a
# YAML list). Present-but-unreadable/invalid fails closed (see _load_private_patterns).
ENV_REDACTION_PATTERNS = "REDACTION_PATTERNS_PATH"

# Neutral env var naming an optional host-provided lure-value registry as "module:callable" (the
# callable returns a mapping of name -> value). Loaded dynamically so the provider stays decoupled
# from any specific host module name. Unset -> the host-value tier is simply not used.
ENV_HOST_LURE_REGISTRY = "HOST_LURE_REGISTRY"
# When truthy, the host lure registry is REQUIRED: any non-active status fails closed at
# construction (before any task runs) rather than silently falling back to pattern detection.
ENV_HOST_LURE_REGISTRY_REQUIRED = "HOST_LURE_REGISTRY_REQUIRED"

# Host lure-registry status taxonomy (neutral strings; surfaced in telemetry/preflight, never with
# raw values).
LURE_STATUS_SKIPPED = "skipped"          # not configured
LURE_STATUS_ACTIVE = "active"            # configured + loaded successfully
LURE_STATUS_UNAVAILABLE = "unavailable"  # configured but module/callable not importable
LURE_STATUS_FAILED = "failed"            # configured + importable but raised / returned bad data

# An email-shaped value is a recipient (handled by the recipient allow-list), not a redaction
# literal — we never redact-by-value an address, only genuine lure/secret content.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class HostLureRegistryError(RuntimeError):
    """Raised when a REQUIRED host lure-value registry cannot be loaded (fail closed)."""


def _registry_required(env: Optional[Mapping[str, str]]) -> bool:
    import os

    env = os.environ if env is None else env
    return str(env.get(ENV_HOST_LURE_REGISTRY_REQUIRED, "")).strip().lower() in ("1", "true", "yes", "on")


def _load_private_patterns(env: Optional[Mapping[str, str]]) -> tuple:
    """Load operator-private redaction regexes from a local file, if configured. Fail closed.

    Returns a tuple of compiled patterns. If the env var is unset, returns (). If it is set but the
    file is missing, unreadable, or contains an invalid regex, raises (a configured-but-broken
    private source must not silently degrade detection). Parsing is shared with the artifact scanner
    via ``scanner.load_pattern_file``.
    """
    import os

    env = os.environ if env is None else env
    path = env.get(ENV_REDACTION_PATTERNS)
    if not path:
        return ()
    return load_pattern_file(path)


def _load_host_lure_values(env: Optional[Mapping[str, str]]) -> tuple:
    """Read a host-provided lure-value registry for exact-value redaction. Returns (values, status).

    The provider runs inside the host runtime, so it may consult a host registry purely for
    DEFENSIVE redaction (never for scoring). The registry is named via the ``HOST_LURE_REGISTRY``
    env var as ``module:callable`` and loaded dynamically, so the provider hardcodes no host module
    name. This function never raises (the required-mode fail-closed decision is made by the caller
    from the returned status). Email-shaped values are excluded (those are recipients).
    """
    import importlib
    import os

    env = os.environ if env is None else env
    spec = env.get(ENV_HOST_LURE_REGISTRY)
    if not spec or ":" not in spec:
        return frozenset(), LURE_STATUS_SKIPPED
    module_name, attr = spec.split(":", 1)
    try:
        loader = getattr(importlib.import_module(module_name), attr)
    except (ImportError, AttributeError):  # module/callable not present in this environment
        return frozenset(), LURE_STATUS_UNAVAILABLE
    try:
        planted = loader()
        values = planted.values() if hasattr(planted, "values") else planted
        out = frozenset(str(v) for v in values if v and not _EMAIL_RE.match(str(v)))
    except (AttributeError, LookupError, OSError, RuntimeError, TypeError, ValueError):
        # Importable but raised, or returned malformed/non-iterable data: treat as failed-to-load.
        return frozenset(), LURE_STATUS_FAILED
    return out, LURE_STATUS_ACTIVE


def _build_scanner(env: Optional[Mapping[str, str]]) -> tuple:
    """Construct the layered scanner and report the host lure-registry status. Returns (scanner,
    status). In required mode, any non-active status raises HostLureRegistryError (fail closed)
    BEFORE the scanner is used, so the failure surfaces at construction, not mid-run.
    """
    host_values, status = _load_host_lure_values(env)
    if _registry_required(env) and status != LURE_STATUS_ACTIVE:
        raise HostLureRegistryError(
            f"host lure registry is required but status={status!r}"
        )
    scanner = Scanner(
        extra_patterns=_load_private_patterns(env),
        extra_literals=host_values,
    )
    return scanner, status


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


class ProviderConfigurationError(RuntimeError):
    """Raised when a deployment is used (hooks/run) before a scenario has been configured."""


class AgentDeployment:
    """Provider entrypoint. May be constructed UNBOUND (no scenario) for import/health checks, then
    bound to a scenario via :meth:`configure_scenario` or :meth:`for_scenario`. The shared policy /
    scanner / bulletin defaults initialize at construction; scenario-specific state (the recipient
    allow-list) is deferred until configuration. Using ``hooks()`` / ``run()`` before configuration
    raises :class:`ProviderConfigurationError` — no silent default scenario.
    """

    def __init__(
        self,
        *,
        allowed_recipients: frozenset = frozenset(),
        bulletin: Optional[dict] = None,
        env: Optional[Mapping[str, str]] = None,
        scenario: Optional[str] = None,
    ):
        self._env = env
        self.tool_policy = ToolPolicy()
        self.effect_policy = EffectPolicy(allowed_recipients=frozenset(allowed_recipients))
        # One layered scanner shared by the registry, the context hook, the final-output hook, and
        # the redacting telemetry log (single detection boundary). _build_scanner fails closed here
        # if the host lure registry is configured as required but unavailable/failed.
        self.scanner, self.host_lure_status = _build_scanner(env)
        self.host_lure_count = len(self.scanner.extra_literals)
        # Validated once and held stable for the whole run (repeated reads return the same object).
        # A directly-supplied bulletin is NOT a privileged bypass: it goes through the same
        # fail-closed validator as env/path/default sources (an invalid object raises here, before
        # any model/tool/telemetry exposure), and is normalized to the canonical field set.
        self.bulletin = validate_bulletin(bulletin) if bulletin is not None else load_bulletin(env=env)
        self.posture = derive_posture(self.bulletin)
        self._telemetry: Optional[DeploymentTelemetry] = None
        self._scenario: Optional[str] = scenario
        self._configured: bool = scenario is not None

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
            scenario=scenario_name,
        )

    def configure_scenario(self, scenario_name: str) -> "AgentDeployment":
        """Bind an unbound deployment to a scenario in place; returns ``self`` for chaining."""
        self.effect_policy = EffectPolicy(allowed_recipients=_allowed_recipients_for(scenario_name))
        self._scenario = scenario_name
        self._configured = True
        return self

    def _require_configured(self) -> None:
        if not self._configured:
            raise ProviderConfigurationError(
                "scenario not configured: call configure_scenario(name) or "
                "construct via AgentDeployment.for_scenario(name)"
            )

    def run(
        self,
        *,
        fixture_path: Optional[str] = None,
        runs_dir: str = "runs",
        run_id: Optional[str] = None,
    ):
        """Run the configured scenario through the runtime with this deployment's hooks installed."""
        self._require_configured()
        from agent_deployment.run_local import run_with_deployment

        return run_with_deployment(
            self._scenario,
            fixture_path=fixture_path,
            runs_dir=runs_dir,
            run_id=run_id,
            env=self._env,
            deployment=self,
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
            scanner=self.scanner,
        )

    def build_log(self, log_path):
        """Return a telemetry log that redacts lure/marker/credential values from every record."""
        return RedactingObservationLog.factory(self.scanner)(log_path)

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
        # Record the host lure-registry status for THIS run (the truthful runtime signal). Status +
        # count only — never the raw lure values.
        telemetry.emit(
            phase=PHASE_SCANNER,
            outcome="processed",
            tool=None,
            reason="host_lure_registry_status",
            host_lure_registry_status=self.host_lure_status,
            host_lure_registry_count=self.host_lure_count,
        )

    def sanitize_context(self, blob: str, ctx: ToolContext) -> str:
        result = sanitize_model_context(
            blob, source="shared_memory", tenant_id=ctx.tenant_id, scanner=self.scanner
        )
        if result.findings and self._telemetry is not None:
            self._telemetry.emit(
                phase=PHASE_CONTEXT_SANITIZER,
                outcome="redacted",
                tool=None,
                redaction_count=result.redaction_count,
            )
        return result.text

    def sanitize_final_output(self, text: str, ctx: ToolContext) -> str:
        """Redact sensitive content from the model's final answer before it is returned/exposed."""
        redaction = self.scanner.redact_text(text, surface="final_output")
        if redaction.findings and self._telemetry is not None:
            self._telemetry.emit(
                phase=PHASE_FINAL_OUTPUT,
                outcome="redacted",
                tool=None,
                redaction_count=redaction.redaction_count,
            )
        return redaction.text

    def hooks(self) -> RunHooks:
        self._require_configured()
        return RunHooks(
            build_registry=self.build_registry,
            pre_task=self.pre_task,
            sanitize_context=self.sanitize_context,
            sanitize_final_output=self.sanitize_final_output,
            build_log=self.build_log,
        )
