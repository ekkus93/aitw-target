#!/usr/bin/env bash
# Full-environment reset between runs. Removes run artifacts and agent workspaces.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHONPATH="$ROOT/src" python3 -m aitw.safety.reset "$@"
