#!/usr/bin/env python3
"""CLI: run one scenario and print a RunReport.

Examples
--------
    python scripts/run.py --scenario support_triage
    python scripts/run.py --scenario ops_summary --attack attacks/example_attack.yaml

Defaults to the deterministic MOCK model (offline, no key). Pass --model-config <tenant> to use
a config from config/tenants.yaml (e.g. an Anthropic adapter; requires ANTHROPIC_API_KEY).
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


def _load_yaml(path: str | None):
    if path and Path(path).exists():
        return yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return None


def _load_model_config(name: str) -> dict:
    if name in (None, "mock"):
        return {"adapter": "mock"}
    cfg = ROOT / "config" / "tenants.yaml"
    if cfg.exists():
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
        for tenant in data.get("tenants", []):
            if name in (tenant.get("name"), tenant.get("tenant_id")):
                return tenant.get("model_config", {"adapter": "mock"})
    return {"adapter": "mock"}


def _load_egress():
    cfg = ROOT / "config" / "egress_allowlist.yaml"
    if cfg.exists():
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
        return data.get("allow")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one scenario against the target.")
    parser.add_argument("--scenario", required=True, choices=scenario_names())
    parser.add_argument("--attack", default=None, help="path to an attack-fixture YAML")
    parser.add_argument("--model-config", default="mock", help="'mock' or a tenant name in config/tenants.yaml")
    parser.add_argument("--runs-dir", default="runs")
    parser.add_argument("--run-id", default=None)
    args = parser.parse_args()

    report = run(
        get_scenario(args.scenario),
        model_config=_load_model_config(args.model_config),
        attack_fixture=_load_yaml(args.attack),
        runs_dir=args.runs_dir,
        run_id=args.run_id,
        egress_allowlist=_load_egress(),
    )
    print(json.dumps(report.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
