#!/usr/bin/env python3
"""CLI: run one scenario and print a RunReport.

Examples
--------
    python scripts/run.py --scenario support_triage
    python scripts/run.py --scenario ops_summary --attack attacks/example_attack.yaml

Defaults to the deterministic MOCK model (offline, no key). Pass --model-config <tenant> to use
a config from config/tenants.yaml (e.g. an Anthropic adapter; requires ANTHROPIC_API_KEY).

Failure model (see AITW_TARGET_HARDENING_SPEC): this CLI is *Boundary A* — pre-run resolution
errors (missing/malformed attack fixture, unknown/malformed model config, invalid run id) print a
clear error to stderr and exit non-zero WITHOUT starting a run or writing any telemetry. Once a run
has started, in-run failures are classified inside the run's telemetry by the harness (Boundary B).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))  # zero-install convenience

import yaml  # noqa: E402

from aitw.orchestrator.run_harness import run  # noqa: E402
from aitw.scenarios import get_scenario, scenario_names  # noqa: E402


class CliError(Exception):
    """A Boundary-A resolution error: report to stderr and exit non-zero, write no telemetry."""


def load_attack_fixture(path: str | None) -> dict | None:
    """Resolve the --attack path to a fixture mapping, or None if --attack was omitted.

    A *provided* path that is missing, unreadable, empty, malformed, or not a mapping is a hard
    error: a typoed attack path must never silently degrade into a clean no-attack run.
    """
    if path is None:
        return None
    p = Path(path)
    if not p.exists():
        raise CliError(f"--attack path does not exist: {path}")
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"--attack path cannot be read: {path} ({exc})") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CliError(f"--attack file is not valid YAML: {path} ({exc})") from exc
    if data is None:
        raise CliError(f"--attack file is empty: {path}")
    if not isinstance(data, dict):
        raise CliError(f"--attack file must be a YAML mapping, got {type(data).__name__}: {path}")
    return data


def load_model_config(name: str) -> dict:
    """Resolve --model-config to a model_config mapping.

    'mock' is the only implicit shortcut. Any other name must resolve to a tenant in
    config/tenants.yaml that explicitly declares a model_config with an adapter. There is NO
    silent fallback to mock: an unknown name, a missing/malformed tenants file, or a tenant with
    no explicit adapter is a hard error. (A tenant that explicitly sets adapter: mock is fine.)
    """
    if name == "mock":
        return {"adapter": "mock"}
    cfg = ROOT / "config" / "tenants.yaml"
    if not cfg.exists():
        raise CliError(f"--model-config {name!r} requires config/tenants.yaml, which is missing")
    try:
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise CliError(f"config/tenants.yaml is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise CliError("config/tenants.yaml must be a mapping with a 'tenants' list")

    known: list[str] = []
    for tenant in data.get("tenants", []) or []:
        if not isinstance(tenant, dict):
            continue
        known.extend(str(v) for v in (tenant.get("name"), tenant.get("tenant_id")) if v)
        if name in (tenant.get("name"), tenant.get("tenant_id")):
            mc = tenant.get("model_config")
            if not isinstance(mc, dict) or not mc.get("adapter"):
                raise CliError(
                    f"tenant {name!r} has no valid model_config.adapter in config/tenants.yaml"
                )
            return mc
    available = ", ".join(sorted(set(known))) or "(none)"
    raise CliError(f"unknown --model-config {name!r}. Use 'mock' or one of: {available}")


def _load_egress():
    cfg = ROOT / "config" / "egress_allowlist.yaml"
    if cfg.exists():
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
        return data.get("allow")
    return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run one scenario against the target.")
    parser.add_argument("--scenario", required=True, choices=scenario_names())
    parser.add_argument("--attack", default=None, help="path to an attack-fixture YAML")
    parser.add_argument("--model-config", default="mock", help="'mock' or a tenant name in config/tenants.yaml")
    parser.add_argument("--runs-dir", default="runs")
    parser.add_argument("--run-id", default=None)
    args = parser.parse_args(argv)

    # Boundary A — resolve inputs before any run starts. Fail loudly, write no telemetry.
    try:
        model_config = load_model_config(args.model_config)
        attack_fixture = load_attack_fixture(args.attack)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        report = run(
            get_scenario(args.scenario),
            model_config=model_config,
            attack_fixture=attack_fixture,
            runs_dir=args.runs_dir,
            run_id=args.run_id,
            egress_allowlist=_load_egress(),
        )
    except ValueError as exc:
        # Pre-telemetry validation (e.g. invalid run id): no run started, no telemetry written.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — in-run failure; harness already wrote end telemetry
        print(f"run failed: {exc!r}", file=sys.stderr)
        return 1

    print(json.dumps(report.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
