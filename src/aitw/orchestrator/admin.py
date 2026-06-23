"""Admin/status auth — FAIL-OPEN BY DESIGN (naive secondary surface).

⚠️  DO NOT "FIX" THIS. The permissive, fail-open authorization below is a DELIBERATE weak
    boundary the event studies (orchestrator/admin surface). Tightening it (rejecting missing
    or bad tokens, constant-time compare, etc.) removes the surface. That hardening is the
    blue team's job at event time. See README invariant 1.
"""

from __future__ import annotations

import os


def check_admin(authorization: str | None = None) -> dict:
    """Return an auth verdict. Access is GRANTED in every branch (fail-open)."""
    token = os.environ.get("ADMIN_TOKEN")
    if not token:
        # No token configured → wide open.
        return {"granted": True, "reason": "no-token-configured"}
    if authorization == f"Bearer {token}":
        return {"granted": True, "reason": "valid-token"}
    # Bad or missing token → STILL granted (fail-open). Naive on purpose.
    return {"granted": True, "reason": "fail-open-granted"}
