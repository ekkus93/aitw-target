"""Sanitization + contract scan for the Round 2 intake artifact (build/QA tool — not shipped).

Walks a built Round 2 artifact directory and fails on anything that must not ship or that violates
the accepted intake contract:

  * the manifest must be exactly ``name: defense`` / ``provider: provider:DEPLOYMENT`` /
    ``declared_secrets: []`` with no extra keys;
  * a root ``provider.py`` must exist and reference ``DEPLOYMENT``;
  * forbidden directories/files (the runtime fork, scenarios, tests, docs, the rich manifest's
    schema/metadata/pyproject, caches, packet/operator docs) must be absent;
  * project/condition label tells, credential shapes, and canary-shaped lure markers must be absent.

Findings report path/kind only — never a raw token value. Run against the directory produced by
``agent_deployment.round2_packaging`` before handoff: it must FAIL on the repo root or the legacy
rich artifact and PASS on a clean minimal artifact.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from agent_deployment.artifact_scan import (
    FORBIDDEN_FILENAME_RES,
    LABEL_TERMS,
    TEXT_SUFFIXES,
    _configured_private_patterns,
)
from agent_deployment.scanner import _LURE_TOKEN_PATTERN, _SECRET_PATTERNS

# The exact accepted manifest. Anything else (missing/extra keys, wrong values) is a finding.
EXPECTED_MANIFEST = {
    "name": "defense",
    "provider": "provider:DEPLOYMENT",
    "declared_secrets": [],
}

# Directory/path components that must never appear in a Round 2 artifact. Stricter than the legacy
# scan: the minimal contract also forbids scenarios/config/data/harm_targets/vendor/schemas and the
# rich-manifest support files (README/metadata/pyproject are checked by name below).
FORBIDDEN_PATH_PARTS = {
    ".git",
    "attacks",
    "scenarios",
    "tests",
    "tmp",
    "docs",
    "pentest",
    "config",
    "data",
    "harm_targets",
    "vendor",
    "schemas",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    ".venv",
    "venv",
    "aitw",  # the underlying runtime fork must not be bundled
}

# Root files that the minimal artifact must not carry (the legacy rich artifact shipped these).
FORBIDDEN_ROOT_FILES = {"README.md", "metadata.json", "pyproject.toml"}

# Additional Round 2 label tells layered on top of the shared LABEL_TERMS.
EXTRA_LABEL_TERMS = (
    "round 2",
    "round2",
    "attack fixture",
    "baseline compromised",
    "operator packet",
    "secret_guard:allow-pattern-literals",
)


@dataclass(frozen=True)
class ScanFinding:
    path: str
    kind: str   # manifest | provider | forbidden_path | forbidden_root_file | forbidden_filename
                # | label | secret | lure_token | private_pattern
    detail: str


def _check_manifest(root: Path) -> list[ScanFinding]:
    mf = root / "deployment.yaml"
    if not mf.is_file():
        return [ScanFinding("deployment.yaml", "manifest", "missing manifest")]
    try:
        data = yaml.safe_load(mf.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [ScanFinding("deployment.yaml", "manifest", f"unparseable: {type(exc).__name__}")]
    if data != EXPECTED_MANIFEST:
        if isinstance(data, dict):
            extra = sorted(set(data) - set(EXPECTED_MANIFEST))
            if extra:
                return [ScanFinding("deployment.yaml", "manifest", f"unexpected keys: {extra}")]
        return [ScanFinding("deployment.yaml", "manifest", "manifest does not match accepted schema")]
    return []


def _check_root_provider(root: Path) -> list[ScanFinding]:
    pv = root / "provider.py"
    if not pv.is_file():
        return [ScanFinding("provider.py", "provider", "missing root provider.py")]
    if "DEPLOYMENT" not in pv.read_text(encoding="utf-8"):
        return [ScanFinding("provider.py", "provider", "root provider.py does not reference DEPLOYMENT")]
    return []


def scan_round2_artifact(root: str | Path) -> list[ScanFinding]:
    root = Path(root).resolve()
    private_patterns = _configured_private_patterns()
    label_terms = list(LABEL_TERMS) + list(EXTRA_LABEL_TERMS)
    findings: list[ScanFinding] = []

    findings.extend(_check_manifest(root))
    findings.extend(_check_root_provider(root))

    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        parts = set(p.relative_to(root).parts)
        bad_part = parts & FORBIDDEN_PATH_PARTS
        if bad_part:
            findings.append(ScanFinding(rel, "forbidden_path", sorted(bad_part)[0]))
            continue
        if p.is_dir():
            continue
        if rel in FORBIDDEN_ROOT_FILES:
            findings.append(ScanFinding(rel, "forbidden_root_file", p.name))
        if any(rx.match(p.name) for rx in FORBIDDEN_FILENAME_RES):
            findings.append(ScanFinding(rel, "forbidden_filename", p.name))
        if p.suffix.lower() in TEXT_SUFFIXES:
            try:
                text = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            low = text.lower()
            for term in label_terms:
                if term in low:
                    findings.append(ScanFinding(rel, "label", term))
            for srx in _SECRET_PATTERNS:
                if srx.search(text):
                    findings.append(ScanFinding(rel, "secret", srx.pattern))
            # Path/kind only — the raw value is never recorded or printed.
            if _LURE_TOKEN_PATTERN.search(text):
                findings.append(ScanFinding(rel, "lure_token", "canary-shaped lure marker present"))
            if any(rx.search(text) for rx in private_patterns):
                findings.append(ScanFinding(rel, "private_pattern", "configured private value present"))
    return findings


def is_clean(root: str | Path) -> bool:
    return not scan_round2_artifact(root)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Scan a Round 2 intake artifact for unsafe content.")
    parser.add_argument("--path", required=True, help="artifact directory to scan")
    args = parser.parse_args(argv)

    findings = scan_round2_artifact(args.path)
    if findings:
        print(f"round2 artifact scan: {len(findings)} issue(s) in {args.path}", file=sys.stderr)
        for f in findings:
            print(f"  [{f.kind}] {f.path}: {f.detail}", file=sys.stderr)
        return 1
    print(f"round2 artifact scan: clean ({args.path})")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
