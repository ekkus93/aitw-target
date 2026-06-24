"""Local runner: execute a scenario through the deployment policy layer.

A thin convenience wrapper for development evidence (baseline vs. deployed comparison). It resolves
a scenario, optional attack fixture, and egress allow-list exactly as the base CLI does, constructs
an ``AgentDeployment`` for the scenario, and runs it through the runtime with the deployment hooks
installed. The base CLI and existing run behavior are untouched.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from aitw.cli import CliError, load_attack_fixture, load_egress
from aitw.orchestrator.run_harness import RunReport, run
from aitw.scenarios import get_scenario, scenario_names

from agent_deployment.provider import AgentDeployment


def run_with_deployment(
    scenario_name: str,
    *,
    attack_path: Optional[str] = None,
    runs_dir: str = "runs",
    run_id: Optional[str] = None,
    env: Optional[dict] = None,
) -> RunReport:
    """Run one scenario through the deployment layer (mock model, offline)."""
    scenario = get_scenario(scenario_name)
    attack_fixture = load_attack_fixture(attack_path) if attack_path else None
    deployment = AgentDeployment.for_scenario(scenario_name, env=env)
    return run(
        scenario,
        attack_fixture=attack_fixture,
        runs_dir=runs_dir,
        run_id=run_id,
        egress_allowlist=load_egress(),
        hooks=deployment.hooks(),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run one scenario through the deployment layer.")
    parser.add_argument("--scenario", required=True, choices=scenario_names())
    parser.add_argument("--attack", default=None, help="path to an attack-fixture YAML")
    parser.add_argument("--runs-dir", default="runs")
    parser.add_argument("--run-id", default=None)
    args = parser.parse_args(argv)

    try:
        report = run_with_deployment(
            args.scenario,
            attack_path=args.attack,
            runs_dir=args.runs_dir,
            run_id=args.run_id,
        )
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — in-run failure; harness already wrote end telemetry
        print(f"run failed: {exc!r}", file=sys.stderr)
        return 1

    print(json.dumps(report.__dict__, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
