"""External-effect validation: validate high-impact effects before any mock sink is mutated.

Even if the model is induced into attempting an effect it should not, that effect must be validated
before the underlying tool runs — so it never appends to ``sent_emails`` / ``scheduled`` /
``fetched`` / ``file_writes`` and therefore never registers as a harmful outcome.

The headline control is recipient allow-listing for ``send_email``: only scenario-derived safe
recipients (e.g. the seeded support-ticket customers) are permitted, so an arbitrary external
address is denied. ``http_fetch`` and ``file_io`` already enforce egress-allowlisting and
workspace/size containment in the underlying tools; the effect policy adds the recipient gate the
base runtime lacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aitw.tools.registry import ToolContext


@dataclass
class EffectDecision:
    allowed: bool
    reason: str
    action: str = "allow"  # allow | deny


@dataclass
class EffectPolicy:
    """Per-run external-effect rules. ``allowed_recipients`` is derived from scenario fixtures by
    the deployment (e.g. the support-triage ticket ``from`` addresses)."""

    allowed_recipients: frozenset[str] = field(default_factory=frozenset)

    def validate_effect(self, name: str, args: dict, *, ctx: ToolContext) -> EffectDecision:
        args = args or {}
        if name == "send_email":
            to = (args.get("to") or "").strip()
            if not to:
                return EffectDecision(False, "email_missing_recipient", "deny")
            # Fail closed: a reachable send_email with no configured allow-list means the recipient
            # set is unknown, so deny rather than permit an arbitrary address. A scenario that
            # legitimately sends email always supplies its recipient allow-list.
            if not self.allowed_recipients:
                return EffectDecision(False, "email_no_allowlist_configured", "deny")
            if to not in self.allowed_recipients:
                return EffectDecision(False, "email_recipient_not_allowed", "deny")
            return EffectDecision(True, "recipient_allowed")
        # Other effect tools (scheduler / http_fetch / file_io) are gated by the tool allow-list and
        # by the underlying tools' own containment controls; no extra recipient-style gate here.
        return EffectDecision(True, "no_effect_constraint")
