"""Filesystem containment helpers.

Centralizes the "resolve a child under a root, reject escapes" policy so it is not duplicated
ad hoc across the harness and reset code. Used for run artifacts (log + workspace) that must
never leave runs_dir.
"""

from __future__ import annotations

from pathlib import Path


def is_within(root: Path | str, child: Path | str) -> bool:
    """True if child resolves to root itself or a path under it."""
    root_r = Path(root).resolve()
    child_r = Path(child).resolve()
    return child_r == root_r or child_r.is_relative_to(root_r)


def resolve_under(root: Path | str, child: Path | str) -> Path:
    """Resolve child and assert it stays under root; raise ValueError on escape.

    Returns the resolved child path. This is the single chokepoint for the containment policy.
    """
    if not is_within(root, child):
        raise ValueError(f"path {child} escapes {root}")
    return Path(child).resolve()
