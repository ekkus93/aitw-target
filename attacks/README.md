# Attack fixtures

An attack fixture is a YAML mapping describing how the run harness plants a payload before the
agent loop runs. It is one of the three parameters of a run: `{scenario, model_config, attack_fixture}`.

See [`example_attack.yaml`](example_attack.yaml) for a working example.

## Schema

| Field | Required | Type | Meaning |
|---|---|---|---|
| `method` | no (defaults to `poison_context`) | string | How the payload is planted — must be a **known method** (below). An unknown method is a hard error, so a typo cannot silently fall back to the default. |
| `name` | no | string | Label for the attack; appears in the observation log `attack` event. |
| `target_tenant` | no (defaults to the running tenant) | string | Which tenant's context to poison. |
| `payload` | no | string | The planted content. |
| `indicator` | no | string | A string whose appearance in a mock **effect sink** signals the attacker's goal was realized; used by the placeholder harm check. |

All string fields are type-checked when present. Validation lives in
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
- Reaches `run()` but has an unknown method or a wrongly-typed field → the run records
  `run_outcome: attack_fixture_error` in its end telemetry record.
