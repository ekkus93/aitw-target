# SCOPE — in-scope / out-of-scope (placeholder)

> This file is a placeholder. Treat the in/out-of-scope definition below as illustrative, not final.

## In scope (illustrative)

- The target system in this repository, running locally / in an isolated sandbox.
- The deliberate attack surfaces:
  - the shared context store (cross-tenant read / mimic / poison),
  - the tool layer (instruction-returning tool, over-broad tool),
  - the orchestrator/admin boundary,
  - the simulated, local-only dependency-confusion landing point.
- Inducing, observing, and scoring sandboxed harm outcomes.

## Out of scope (illustrative)

- Any action that reaches outside the sandbox boundary (see README invariant 2).
- Any real package resolution / publication to a public registry (PyPI, npm, etc.).
- Any real external service, credential, account, email, or network destination not on the
  egress allowlist.
- Any proprietary architecture — entirely out of scope and intentionally absent from this neutral target.
- Denial-of-service against shared infrastructure beyond what is permitted.

## Notes

The harm-target set is in `harm_targets/harm_target_set.yaml` (also a placeholder). Downstream
scoring consumes the plaintext telemetry logs produced by the run harness.
