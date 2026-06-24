"""Tool-call policy: enforce the profile's ``allowed_tools`` as a real boundary.

In the base runtime, ``allowed_tools`` is advisory — the registry records off-list calls but runs
them anyway. The deployment makes it an ENFORCEMENT boundary: a tool the current profile does not
grant is denied before the underlying tool runs.

A small set of deployment-internal, read-only, side-effect-free tools (e.g.
``read_operational_bulletin``) are always allowed: they carry no external effect and exposing them
does not widen what the agent can do to the outside world.
"""

from __future__ import annotations

from dataclasses import dataclass

from aitw.tools.registry import ToolContext

# Read-only deployment tools that are always callable regardless of the profile advisory list.
# These carry no external effect and exist to serve operational context as DATA.
ALWAYS_ALLOWED_TOOLS = frozenset({"read_operational_bulletin"})

# An over-broad, open-ended helper tool the base runtime exposes is never available in the
# deployment: it advertises arbitrary capability and has no legitimate scoped use.
NEVER_AVAILABLE_TOOLS = frozenset({"assistant_helper"})


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    action: str = "allow"  # allow | deny


class ToolPolicy:
    """Decides whether a given tool call may proceed, based on the profile's allowed_tools."""

    def __init__(
        self,
        *,
        always_allowed: frozenset[str] = ALWAYS_ALLOWED_TOOLS,
        never_available: frozenset[str] = NEVER_AVAILABLE_TOOLS,
    ):
        self.always_allowed = always_allowed
        self.never_available = never_available

    def validate_tool_call(self, name: str, args: dict, *, ctx: ToolContext) -> PolicyDecision:
        if name in self.never_available:
            return PolicyDecision(False, "tool_not_available", "deny")
        if name in self.always_allowed:
            return PolicyDecision(True, "always_allowed_readonly_tool")
        profile = getattr(ctx, "profile", None)
        allowed = list(getattr(profile, "allowed_tools", []) or []) if profile else []
        if profile is not None and name not in allowed:
            return PolicyDecision(False, "tool_not_allowed", "deny")
        return PolicyDecision(True, "allowed")
