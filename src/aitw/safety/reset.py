"""Environment reset / teardown between runs (Invariant 2: nothing escapes the box).

Removes run artifacts and agent workspaces so each run starts clean. Guarded: it only removes
directories literally named in SAFE_NAMES, so a mistyped path can't nuke the repo.

A REFUSED or FAILED target makes the CLI exit non-zero (FIX2 P1.12): automation must be able to
tell that a requested teardown did not happen — a refusal that looks successful is a footgun.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

SAFE_NAMES = {"runs", "workspaces"}
# Repo root: .../agents-in-the-wild/src/aitw/safety/reset.py -> parents[3].
PROJECT_ROOT = Path(__file__).resolve().parents[3]


@dataclass
class ResetResult:
    removed: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.refused and not self.failed


def reset_targets(targets: tuple[str, ...] = ("runs", "workspaces")) -> ResetResult:
    """Attempt to remove each target, recording removed / refused / failed.

    Two guards, BOTH required: an allowed basename AND containment under the project root. The
    basename check alone let an absolute "/anything/runs" through to rmtree.
    """
    result = ResetResult()
    for name in targets:
        path = Path(name).resolve()
        if path.name not in SAFE_NAMES or not path.is_relative_to(PROJECT_ROOT):
            print(
                f"reset: refusing to remove path outside the project run dirs: {path}",
                file=sys.stderr,
            )
            result.refused.append(str(path))
            continue
        if path.exists():
            try:
                shutil.rmtree(path)
            except OSError as exc:
                print(f"reset: FAILED to remove {path}: {exc}", file=sys.stderr)
                result.failed.append(str(path))
                continue
            result.removed.append(str(path))
    return result


def reset(targets: tuple[str, ...] = ("runs", "workspaces")) -> list[str]:
    """Back-compat helper: return only the list of removed paths."""
    return reset_targets(targets).removed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Reset run artifacts / workspaces.")
    parser.add_argument(
        "targets",
        nargs="*",
        default=None,
        help=f"directories to remove (allowlisted basenames: {', '.join(sorted(SAFE_NAMES))})",
    )
    args = parser.parse_args(argv)
    targets = tuple(args.targets) if args.targets else ("runs", "workspaces")

    result = reset_targets(targets)
    if result.removed:
        print("reset removed:\n  " + "\n  ".join(result.removed))
    elif result.ok:
        print("reset: nothing to remove (clean)")
    # Refused/failed targets must surface as a non-zero exit so automation can detect them.
    if not result.ok:
        print(
            f"reset: {len(result.refused)} refused, {len(result.failed)} failed",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
