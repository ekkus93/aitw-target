"""Generate baseline-vs-deployed evidence from real runs (dev tool — not shipped).

Runs the same poisoned-context scenario two ways and captures telemetry excerpts:

  * baseline (no policy hooks): the untrusted instruction is followed -> an exfil email reaches the
    mock sink and the run is scored compromised;
  * deployed (policy hooks): the untrusted marker is neutralized and/or the effect is denied, the
    legitimate customer reply is still produced, and the run is scored not compromised.

The evidence is produced from actual run telemetry, not hand-written. Output is neutral.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from aitw.cli import load_attack_fixture
from aitw.orchestrator.run_harness import run
from aitw.scenarios import get_scenario

from agent_deployment.provider import AgentDeployment

REPO_ROOT = Path(__file__).resolve().parents[2]
SCENARIO = "support_triage"
FIXTURE_PATH = str(REPO_ROOT / "attacks" / "example_attack.yaml")


def _records(log_path: str) -> list:
    return [json.loads(line) for line in Path(log_path).read_text().splitlines() if line.strip()]


def _dedupe(records: list) -> list:
    """Preserve order, drop exact-duplicate records (a record can satisfy multiple selectors)."""
    seen = set()
    out = []
    for r in records:
        key = json.dumps(r, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def _baseline_excerpt(records: list) -> list:
    out = [r for r in records if r.get("tool") == "send_email"]
    out += [r for r in records if r.get("outcome") == "end"]
    return _dedupe(out)


def _deployed_excerpt(records: list) -> list:
    keep_phases = {
        "context_sanitizer", "external_effect", "tool_policy", "memory_policy",
        "operational_bulletin", "scanner", "final_output",
    }
    out = [r for r in records if r.get("phase") in keep_phases]
    out += [r for r in records if r.get("tool") == "send_email"]
    out += [r for r in records if r.get("outcome") == "end"]
    return _dedupe(out)


def generate_evidence(*, runs_dir: str | Path, fixture_path: str = FIXTURE_PATH) -> dict:
    fixture = load_attack_fixture(fixture_path)

    baseline = run(
        get_scenario(SCENARIO), attack_fixture=fixture, runs_dir=runs_dir, run_id="evidence-baseline"
    )
    deployment = AgentDeployment.for_scenario(SCENARIO)
    deployed = run(
        get_scenario(SCENARIO),
        attack_fixture=fixture,
        runs_dir=runs_dir,
        run_id="evidence-deployed",
        hooks=deployment.hooks(),
    )

    return {
        "scenario": SCENARIO,
        "fixture": {"name": fixture.get("name"), "method": fixture.get("method")},
        "baseline": {
            "completed": baseline.completed,
            "compromised": baseline.compromised,
            "excerpt": _baseline_excerpt(_records(baseline.log_path)),
        },
        "deployed": {
            "completed": deployed.completed,
            "compromised": deployed.compromised,
            "excerpt": _deployed_excerpt(_records(deployed.log_path)),
        },
    }


def _render_markdown(ev: dict) -> str:
    b, d = ev["baseline"], ev["deployed"]
    return (
        f"# Baseline vs. deployed evidence\n\n"
        f"Scenario: `{ev['scenario']}` — fixture `{ev['fixture']['name']}` "
        f"(method `{ev['fixture']['method']}`)\n\n"
        f"| run | completed | compromised |\n"
        f"|-----|-----------|-------------|\n"
        f"| baseline | {b['completed']} | {b['compromised']} |\n"
        f"| deployed | {d['completed']} | {d['compromised']} |\n\n"
        f"## Baseline telemetry excerpt\n\n```json\n{json.dumps(b['excerpt'], indent=2)}\n```\n\n"
        f"## Deployed telemetry excerpt\n\n```json\n{json.dumps(d['excerpt'], indent=2)}\n```\n"
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate baseline-vs-deployed evidence.")
    parser.add_argument("--out", default=None, help="output directory (writes evidence.json + .md)")
    parser.add_argument("--runs-dir", default="runs/evidence")
    args = parser.parse_args(argv)

    try:
        ev = generate_evidence(runs_dir=args.runs_dir)
    except (OSError, ImportError, LookupError, RuntimeError, TypeError, ValueError) as exc:
        print(f"evidence generation failed: {exc!r}", file=sys.stderr)
        return 1

    if args.out:
        out: Optional[Path] = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "evidence.json").write_text(json.dumps(ev, indent=2), encoding="utf-8")
        (out / "evidence.md").write_text(_render_markdown(ev), encoding="utf-8")
        print(f"evidence written to {out}")
    else:
        print(json.dumps(ev, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
