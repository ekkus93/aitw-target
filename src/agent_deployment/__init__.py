"""A defended deployment layer for the multi-tenant agent runtime.

This package is a self-contained policy layer that sits on top of the agent runtime. Rather than
changing the runtime's behavior in place, it supplies policy-enforcing implementations through the
runtime's narrow ``RunHooks`` seams (see ``aitw.orchestrator.run_harness.RunHooks``):

  * an enforced tool allow-list — a tool the current profile does not grant is denied before it
    runs, not merely recorded;
  * tenant-scoped shared memory — reads, lists, and searches outside the calling tenant are denied
    or redacted;
  * context provenance + sanitization — content from memory, tool output, search, or the bulletin
    is framed as untrusted data and control tokens are neutralized before the model sees it;
  * external-effect validation — high-impact effects (email recipients, etc.) are validated before
    any mock sink is mutated;
  * an operational-bulletin interface — a read-only, schema-validated pre-task object that the
    deployment treats as data and may key its posture off of.

The safeguards are always on. Bulletin-derived posture only tunes strictness and logging detail; it
never decides whether a core control fires. Everything is defined by code and configuration with no
manual runtime steps.
"""

from __future__ import annotations

from agent_deployment.provider import AgentDeployment

__all__ = ["AgentDeployment"]
