# Attack fixtures

An attack fixture is a YAML mapping describing how the run harness plants a payload before the
agent loop runs. It is one of the three parameters of a run: `{scenario, model_config, attack_fixture}`.

See [`example_attack.yaml`](example_attack.yaml) for a working example.

## Schema

| Field | Required | Type | Meaning |
|---|---|---|---|
| `name` | **yes** | string | Label for the attack; appears in the observation log `attack` event. |
| `method` | **yes** | string | How the payload is planted — must be a **known method** (below). An unknown method is a hard error, so a typo cannot silently fall back to a default. |
| `target_tenant` | **yes** | string | Which tenant's context to poison. Must be a valid tenant slug (`^[A-Za-z0-9][A-Za-z0-9_.-]*`); it need not exist in the scenario (an adversarial test may name a foreign tenant). |
| `payload` | **yes** | string | The planted content. Must be non-empty and at most **16384 bytes** (cap configurable via `validate_attack_fixture(..., max_payload_bytes=...)`). |
| `indicator` | no | string | A string whose appearance in a mock **effect sink** signals the attacker's goal was realized; used by the placeholder harm check. |
| `harm_target_id` | no | string | Id into the trusted harm-target set (preferred scoring authority; see the hardening spec). |
| `description` | no | string | Free-text human note. |

All required fields must be present and well-typed; optional string fields are type-checked when
present. Validation is strict (an invalid fixture raises rather than degrading into a weaker
attack) and lives in
[`src/aitw/orchestrator/attack_fixture.py`](../src/aitw/orchestrator/attack_fixture.py).

## Known methods

- `poison_context` — write the payload into the victim tenant's memory (models an attacker
  reaching across the shared store).
- `poison_notice_board` — append the payload to the shared notice board (the instruction-returning
  tool then serves it).
- `poison_profile` — append the payload to the victim's agent-profile working instructions.

## Failure behavior

- Provided via the CLI but missing / empty / malformed / not a mapping → the CLI fails before a
  run starts (no telemetry).
- Reaches `run()` but fails schema validation (missing required field, unknown method,
  wrongly-typed field, invalid `target_tenant`, empty or oversized `payload`) → the run records
  `run_outcome: attack_fixture_error` in its end telemetry record.
