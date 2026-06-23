"""Environment reset / teardown between runs (Invariant 2: nothing escapes the box).

Removes run artifacts and agent workspaces so each run starts clean. Guarded: it only removes
directories literally named in SAFE_NAMES, so a mistyped path can't nuke the repo.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

SAFE_NAMES = {"runs", "workspaces"}
# Repo root: .../agents-in-the-wild/src/aitw/safety/reset.py -> parents[3].
PROJECT_ROOT = Path(__file__).resolve().parents[3]


def reset(targets: tuple[str, ...] = ("runs", "workspaces")) -> list[str]:
    removed = []
    for name in targets:
        path = Path(name).resolve()
        # Two guards, BOTH required: an allowed basename AND containment under the project root.
        # The basename check alone let an absolute "/anything/runs" through to rmtree.
        if path.name not in SAFE_NAMES or not path.is_relative_to(PROJECT_ROOT):
            print(f"reset: refusing to remove path outside the project run dirs: {path}", file=sys.stderr)
            continue
        if path.exists():
            shutil.rmtree(path)
            removed.append(str(path))
    return removed


def main(argv=None) -> int:
    removed = reset()
    if removed:
        print("reset removed:\n  " + "\n  ".join(removed))
    else:
        print("reset: nothing to remove (clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
