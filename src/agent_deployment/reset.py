"""Reset the deployment to a clean state between runs.

Removes regenerable run artifacts (per-run logs and per-run workspaces). Each run already writes
to its own run id, so logs are separated by run; reset clears the accumulated artifact directories
so the next run starts clean. Memory/state, the mock external-effect sinks, and the per-run
bulletin object are all in-process and rebuilt fresh on each run, so there is nothing persistent to
clear for those.

Two guards, BOTH required before anything is removed: the target's basename must be allow-listed
AND it must resolve under the deployment root. A refused or failed target makes the command exit
non-zero so automation can tell the teardown did not happen.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Only these directory basenames may be removed.
SAFE_NAMES = {"runs", "workspaces"}


@dataclass
class ResetResult:
    removed: list = field(default_factory=list)
    refused: list = field(default_factory=list)
    failed: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.refused and not self.failed


def reset_targets(
    targets: tuple = ("runs", "workspaces"), *, root: Path | None = None
) -> ResetResult:
    """Remove each allow-listed target under ``root`` (default: current working directory)."""
    root = (root or Path.cwd()).resolve()
    result = ResetResult()
    for name in targets:
        path = (root / name if not Path(name).is_absolute() else Path(name)).resolve()
        if path.name not in SAFE_NAMES or not path.is_relative_to(root):
            print(f"reset: refusing target outside the deployment run dirs: {path}", file=sys.stderr)
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Reset deployment run artifacts / workspaces.")
    parser.add_argument(
        "targets",
        nargs="*",
        help=f"directories to remove (allow-listed basenames: {', '.join(sorted(SAFE_NAMES))})",
    )
    parser.add_argument("--root", default=None, help="deployment root (default: current directory)")
    args = parser.parse_args(argv)
    targets = tuple(args.targets) if args.targets else ("runs", "workspaces")

    result = reset_targets(targets, root=Path(args.root) if args.root else None)
    if result.removed:
        print("reset removed:\n  " + "\n  ".join(result.removed))
    elif result.ok:
        print("reset: nothing to remove (clean)")
    if not result.ok:
        print(f"reset: {len(result.refused)} refused, {len(result.failed)} failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
