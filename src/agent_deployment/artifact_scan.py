"""Sanitization scan for an exported artifact (build/QA tool — not shipped).

Walks a built artifact directory and fails on anything that must not ship: forbidden directories,
operator/packet document filenames, the underlying runtime fork, credential shapes, and
project/condition label tells in file content. Intended to be run against the directory produced by
``agent_deployment.packaging`` before handoff: it must FAIL on the full development tree and PASS on
a clean artifact.

This module legitimately contains the label tells it searches for (like the repository's own
secret guard), which is exactly why it is a dev-only tool and is excluded from the shipped artifact.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from agent_deployment.scanner import _SECRET_PATTERNS

# Directory/path components that must never appear in a clean artifact.
FORBIDDEN_PATH_PARTS = {
    ".git",
    "attacks",
    "tmp",
    "docs",
    "pentest",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    ".venv",
    "venv",
    "aitw",  # the underlying runtime fork must not be bundled
}

# Operator/packet document filename shapes.
FORBIDDEN_FILENAME_RES = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r".*_spec\.md$",
        r".*_todo\.md$",
        r"responses.*\.md$",
        r"replies.*\.md$",
        r"^\d\d-.*\.md$",     # numbered packet docs, e.g. 02-..., 07-...
        r"test-output.*\.txt$",  # saved local test-run outputs (operator-only, never ship)
    )
]

# Project / condition / methodology label tells (case-insensitive substring match).
#
# These are SPECIFIC tells of this project/event/target — not generic security vocabulary.
# Words like "attacker", "compromise", or "exfiltrate" are ordinary threat-modeling language a
# production deployment legitimately uses, so they are intentionally NOT here. The runtime package
# name ("aitw") is checked at the PATH level only (FORBIDDEN_PATH_PARTS) — the thin artifact still
# imports the provided runtime by name, so flagging that import as content would be a false tell.
LABEL_TERMS = [
    "agents in the wild",
    "agents-in-the-wild",
    "do not fix",
    'do not "fix"',
    "naive by design",
    "naive on purpose",
    "intentional weakness",
    "deliberate weakness",
    "blue team",
    "red team",
    "prong c",
    "day-zero",
    "day zero",
    "honeytoken",
]

# The canonical bulletin schema is the one packet file allowed to be vendored verbatim; its $id is
# an event URI that the contract requires kept byte-identical. Exempt it from the label scan only
# (it is still checked for forbidden paths and credential shapes).
LABEL_EXEMPT_PATHS = {"schemas/operational_bulletin.schema.json"}

TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".json", ".txt", ".cfg", ".ini", ".toml"}


@dataclass(frozen=True)
class ScanFinding:
    path: str
    kind: str   # forbidden_path | forbidden_filename | label | secret
    detail: str


def scan_artifact(root: str | Path) -> list[ScanFinding]:
    root = Path(root).resolve()
    findings: list[ScanFinding] = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        parts = set(p.relative_to(root).parts)
        bad_part = parts & FORBIDDEN_PATH_PARTS
        if bad_part:
            findings.append(ScanFinding(rel, "forbidden_path", sorted(bad_part)[0]))
            continue
        if p.is_dir():
            continue
        if any(rx.match(p.name) for rx in FORBIDDEN_FILENAME_RES):
            findings.append(ScanFinding(rel, "forbidden_filename", p.name))
        if p.suffix.lower() in TEXT_SUFFIXES:
            try:
                text = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if rel not in LABEL_EXEMPT_PATHS:
                low = text.lower()
                for term in LABEL_TERMS:
                    if term in low:
                        findings.append(ScanFinding(rel, "label", term))
            for srx in _SECRET_PATTERNS:
                if srx.search(text):
                    findings.append(ScanFinding(rel, "secret", srx.pattern))
    return findings


def is_clean(root: str | Path) -> bool:
    return not scan_artifact(root)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Scan an exported artifact for unsafe content.")
    parser.add_argument("--path", required=True, help="artifact directory to scan")
    args = parser.parse_args(argv)

    findings = scan_artifact(args.path)
    if findings:
        print(f"artifact scan: {len(findings)} issue(s) in {args.path}", file=sys.stderr)
        for f in findings:
            print(f"  [{f.kind}] {f.path}: {f.detail}", file=sys.stderr)
        return 1
    print(f"artifact scan: clean ({args.path})")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
