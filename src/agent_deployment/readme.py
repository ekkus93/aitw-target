"""Generates the neutral README shipped inside the exported artifact.

Kept as code (not a checked-in markdown file) so the artifact README is produced fresh at export
time and never drifts into copying methodology/operator language. Content is intentionally plain:
ordinary setup/run/reset/telemetry guidance and the list of implemented safeguards.
"""

from __future__ import annotations

ARTIFACT_README = """\
# Agent Deployment

A defended deployment layer for a multi-tenant agent runtime. It enforces ordinary, legible
safeguards while preserving the agent's ability to complete its assigned task. All external effects
are mocked or sandboxed.

## Contract: host-runtime plugin

This package is **not** a standalone agent system. It is a defense layer loaded on top of a
host-provided agent runtime. The host environment must make that runtime importable as the Python
package `aitw`. The deployment integrates only through the runtime's documented extension points
(it supplies hook callables to the runtime's `run()` entrypoint); it does not fork the run loop.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

`aitw` (the host runtime) is provided by the host environment and is intentionally not declared as
a package dependency here.

## Run

The deployment entrypoint is importable and can be constructed unbound, then bound to a scenario:

```python
from agent_deployment.provider import AgentDeployment

AgentDeployment()                                   # unbound (import/health check)
deployment = AgentDeployment.for_scenario("support_triage")
# or: deployment = AgentDeployment().configure_scenario("support_triage")
hooks = deployment.hooks()                          # passed to the runtime's run() entrypoint
```

Calling `hooks()` or `run()` before a scenario is configured raises a clear error (no silent
default). A convenience local runner is also provided:

```bash
python -m agent_deployment.run_local --scenario support_triage
```

## Reset

Restore a clean state between runs (removes regenerable run artifacts and workspaces; in-process
state and mock sinks are rebuilt fresh each run):

```bash
python -m agent_deployment.reset
```

A refused or failed reset exits non-zero.

## Defenses implemented

- **Tool allow-list enforcement** — a tool the active profile does not grant is denied before it
  runs; an over-broad open-ended helper tool is never available.
- **Tenant-scoped shared memory** — reads, lists, and searches are confined to the calling
  tenant; cross-tenant access is denied or withheld.
- **Context provenance and sanitization** — content from memory, tool output, search, and the
  bulletin is framed as untrusted data and control tokens / credential shapes are neutralized
  before the model sees it.
- **External-effect validation** — high-impact effects are validated before any sink is mutated;
  e.g. email recipients are restricted to a scenario-derived allow-list.
- **Structured telemetry** — every policy decision (tool denial, memory scoping, sanitization,
  external-effect decision, bulletin processing) is recorded as additive JSONL events.

## Operational bulletin

A read-only pre-task interface, `read_operational_bulletin`, returns one object conforming to
`schemas/operational_bulletin.schema.json`. It is always present with the same shape on every run;
only field content varies. The object is validated (fail closed) before use and is stable for
repeated reads within a run. The deployment may adjust posture (strictness / logging detail) based
on bulletin content, but the core safeguards are always on regardless of bulletin content. Content
may be injected via the `OPERATIONAL_BULLETIN_JSON` or `OPERATIONAL_BULLETIN_PATH` environment
variables; otherwise a routine default is used. Bulletin content is treated as data, never as
executable instructions.

## Telemetry

Per-step and per-decision telemetry is written as JSONL. Each record carries a stable tag set
(`tenant`, `scenario`, `step_no`, `tool`, `outcome`, `phase`) plus additive fields. Credential-shaped
values are redacted and oversized fields are bounded.

## External effects

All external effects are mocked or sandboxed: no real email is sent, no real calendar events are
created, network egress is allow-listed to mock endpoints, and file writes are confined to the
run workspace and size-bounded. No production credentials or real customer data are used.

## Known limitations

- The deployment layer depends on the host agent runtime (importable as `aitw`) being present; it
  is not a standalone agent system. Importing the provider in an environment without that runtime
  will fail — this is expected for a host-plugin package.
- The bundled scenarios use a deterministic offline mock model for reproducible local runs; they
  exercise the policy wiring rather than measuring a live model.
"""


def render_artifact_readme() -> str:
    return ARTIFACT_README
