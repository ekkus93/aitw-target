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
from urllib.parse import urlsplit

from aitw.tools.registry import ToolContext

# Default ports per scheme — mirrors the stock ``aitw.tools.http_fetch`` authority predicate so the
# deployment's egress decision matches the underlying tool's containment semantics.
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _authority(url: str):
    """Return ``(scheme, host, port)`` for an http(s) URL, or ``None`` if it can't be resolved.

    A LOCAL copy of the stock ``aitw.tools.http_fetch._authority`` predicate (same scheme/host/port
    normalization and default-port handling), so the shipped artifact does not import a private
    stock-runtime symbol. Non-http(s) or unparseable input returns ``None`` and therefore can never
    match an allow-list entry (which resolves through the same function) — i.e. it fails closed.
    """
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            return None
        host = (parts.hostname or "").lower()
        if not host:
            return None
        port = parts.port if parts.port is not None else _DEFAULT_PORTS[scheme]
    except ValueError:  # malformed port / authority
        return None
    return (scheme, host, port)


def _egress_allowed(url: str, allowlist) -> bool:
    """True only if the URL's (scheme, host, port) exactly matches an allow-list entry.

    Uses the local authority predicate so the deployment's egress decision matches the underlying
    tool's containment semantics (a real client / redirect target must satisfy the same host/port
    match). Anything unparseable fails closed.
    """
    allowed = {_authority(entry) for entry in (allowlist or [])}
    allowed.discard(None)
    target = _authority(url)
    return target is not None and target in allowed


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
        if name == "http_fetch":
            # Second-layer egress validation (the underlying tool also enforces this): deny any
            # fetch whose target is not on the run's egress allow-list, before the tool runs.
            if not _egress_allowed(args.get("url", ""), getattr(ctx, "egress_allowlist", [])):
                return EffectDecision(False, "egress_not_allowlisted", "deny")
            return EffectDecision(True, "egress_allowed")
        # Other effect tools (scheduler / file_io) are gated by the tool allow-list and by the
        # underlying tools' own containment controls (workspace confinement, size caps).
        return EffectDecision(True, "no_effect_constraint")
