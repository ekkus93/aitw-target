#!/usr/bin/env python3
"""Thin CLI wrapper. The implementation lives in aitw.cli (so its loaders are unit-testable).

Examples
--------
    python scripts/run.py --scenario support_triage
    python scripts/run.py --scenario ops_summary --attack attacks/example_attack.yaml

Defaults to the deterministic MOCK model (offline, no key). Pass --model-config <tenant> to use
a config from config/tenants.yaml (e.g. an Anthropic adapter; requires ANTHROPIC_API_KEY).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))  # zero-install convenience

from aitw.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
