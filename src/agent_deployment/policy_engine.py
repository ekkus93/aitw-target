"""Central provider policy boundary.

A thin facade over the existing, separately-tested policy modules (tool allow-list, external-effect
rules, tenant-scoped memory, the central scanner, and the context sanitizer). It does NOT
reimplement those checks — it routes every sensitive decision through one place so the registry,
the context hook, the final-output hook, and the telemetry log all consult the same boundary.

Decision objects are structured and telemetry-ready. ``action`` is one of allow | deny | redact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from aitw.tools.registry import ToolContext

from agent_deployment.external_effects import EffectPolicy
from agent_deployment.memory_policy import run_scoped_memory
from agent_deployment.policy import PolicyDecision, ToolPolicy
from agent_deployment.sanitizer import SanitizationResult, sanitize_model_context
from agent_deployment.scanner import RedactionResult, Scanner

# Effect tools whose serialized args are content-scanned before the sink is mutated. http_fetch is
# special-cased to DENY on any sensitive marker (a URL/query cannot be safely redacted without
# changing the egress target); the others redact in place when the action is otherwise authorized.
_DENY_ON_MARKER = frozenset({"http_fetch"})


@dataclass(frozen=True)
class EffectArgScan:
    action: str                 # allow | deny | redact
    args: dict                  # original (allow/deny) or redacted (redact) args
    reason: str
    redaction_count: int = 0
    findings: tuple = field(default_factory=tuple)


class ProviderPolicy:
    """Single boundary the registry and hooks consult for every sensitive decision."""

    def __init__(
        self,
        *,
        tool_policy: ToolPolicy,
        effect_policy: EffectPolicy,
        scanner: Optional[Scanner] = None,
    ):
        self.tool_policy = tool_policy
        self.effect_policy = effect_policy
        self.scanner = scanner or Scanner()

    # --- tool / effect / memory authorization (delegate) -------------------------------------

    def authorize_tool_call(self, ctx: ToolContext, name: str, args: dict) -> PolicyDecision:
        return self.tool_policy.validate_tool_call(name, args or {}, ctx=ctx)

    def authorize_external_effect(self, ctx: ToolContext, name: str, args: dict):
        return self.effect_policy.validate_effect(name, args or {}, ctx=ctx)

    def authorize_memory_access(self, ctx: ToolContext, args: dict, emit=None) -> str:
        # The scoped-memory implementation already encodes the read/list/search/write rules and
        # emits structured denials/redactions through ``emit``.
        return run_scoped_memory(args or {}, ctx, emit)

    # --- scanning / redaction (central scanner) ----------------------------------------------

    def sanitize_model_context(self, ctx: ToolContext, text: str, *, source: str) -> SanitizationResult:
        return sanitize_model_context(
            text, source=source, tenant_id=ctx.tenant_id, scanner=self.scanner
        )

    def scan_output(self, ctx: ToolContext, surface: str, text: str) -> RedactionResult:
        """Redact untrusted text headed to the model / final output / a log."""
        if not isinstance(text, str):
            return RedactionResult(text, [])
        return self.scanner.redact_text(text, surface=surface)

    def scan_effect_args(self, ctx: ToolContext, name: str, args: dict) -> EffectArgScan:
        """Scan serialized effect args for sensitive markers before the sink is mutated.

        Returns an allow/deny/redact decision. For redact, ``args`` is a new dict with string
        fields neutralized so the mock sink only ever sees the redacted content.
        """
        args = args or {}
        serialized = json.dumps(args, default=str, sort_keys=True)
        findings = self.scanner.scan_text(serialized, surface="external_effect_args")
        if not findings:
            return EffectArgScan("allow", args, "no_sensitive_marker")

        if name in _DENY_ON_MARKER:
            return EffectArgScan("deny", args, "effect_contains_sensitive_marker", findings=tuple(findings))

        redacted = {}
        count = 0
        for k, v in args.items():
            if isinstance(v, str):
                r = self.scanner.redact_text(v, surface="external_effect_args")
                redacted[k] = r.text
                count += r.redaction_count
            else:
                redacted[k] = v
        return EffectArgScan(
            "redact", redacted, "effect_args_redacted", redaction_count=count, findings=tuple(findings)
        )

    def redact_for_telemetry(self, value):
        """Recursively neutralize lure/marker/credential content in a telemetry value."""
        if isinstance(value, str):
            return self.scanner.redact_text(value, surface="telemetry").text
        if isinstance(value, dict):
            return {k: self.redact_for_telemetry(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact_for_telemetry(v) for v in value]
        return value
