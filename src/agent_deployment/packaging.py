"""Build a clean export artifact from an allow-list (build tool — not shipped).

Produces a minimal, neutral artifact directory containing only what the deployment needs: the
manifest, the vendored bulletin schema, the runtime policy-layer modules, a freshly generated
neutral README, and a minimal neutral ``pyproject.toml``. It deliberately does NOT copy from the
full working tree — only the explicit allow-list below — and never includes the underlying runtime
fork, operator/packet docs, attacks, caches, or the dev/build tools (this module, the evidence
generator, and the artifact scan).

After building, ``export()`` runs the sanitization scan and refuses to return an artifact that is
not clean.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from agent_deployment.artifact_scan import scan_artifact
from agent_deployment.metadata import write_metadata
from agent_deployment.readme import render_artifact_readme

REPO_ROOT = Path(__file__).resolve().parents[2]

# Runtime policy-layer modules that ship. The dev/build tools (packaging, artifact_scan, evidence)
# are intentionally excluded.
SHIP_MODULES = (
    "__init__.py",
    "provider.py",
    "policy.py",
    "memory_policy.py",
    "sanitizer.py",
    "scanner.py",
    "bulletin.py",
    "registry.py",
    "external_effects.py",
    "telemetry.py",
    "reset.py",
    "run_local.py",
)

_PYPROJECT = """\
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "agent-deployment"
version = "0.1.0"
description = "Defended deployment layer for a multi-tenant agent runtime"
requires-python = ">=3.10"

[tool.setuptools.packages.find]
where = ["src"]
"""


def build_artifact(out_dir: str | Path, *, repo_root: str | Path | None = None) -> Path:
    """Assemble the artifact tree at ``out_dir`` (replacing it if it exists)."""
    repo_root = Path(repo_root or REPO_ROOT)
    out = Path(out_dir)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    shutil.copy2(repo_root / "deployment.yaml", out / "deployment.yaml")

    (out / "schemas").mkdir()
    shutil.copy2(
        repo_root / "schemas" / "operational_bulletin.schema.json",
        out / "schemas" / "operational_bulletin.schema.json",
    )

    pkg = out / "src" / "agent_deployment"
    pkg.mkdir(parents=True)
    for module in SHIP_MODULES:
        shutil.copy2(repo_root / "src" / "agent_deployment" / module, pkg / module)

    (out / "README.md").write_text(render_artifact_readme(), encoding="utf-8")
    (out / "pyproject.toml").write_text(_PYPROJECT, encoding="utf-8")
    write_metadata(out / "metadata.json")
    return out


def export(out_dir: str | Path, *, repo_root: str | Path | None = None, verify: bool = True) -> Path:
    """Build the artifact and, unless ``verify`` is False, fail if the scan finds anything."""
    out = build_artifact(out_dir, repo_root=repo_root)
    if verify:
        findings = scan_artifact(out)
        if findings:
            detail = "; ".join(f"[{f.kind}] {f.path}: {f.detail}" for f in findings[:20])
            raise RuntimeError(f"artifact failed sanitization scan: {detail}")
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Export a clean deployment artifact.")
    parser.add_argument("--out", default="dist/agent-deployment", help="output directory")
    parser.add_argument("--no-verify", action="store_true", help="skip the sanitization scan")
    parser.add_argument("--zip", action="store_true", help="also produce a .zip of the artifact")
    args = parser.parse_args(argv)

    try:
        out = export(args.out, verify=not args.no_verify)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"export failed: {exc}", file=sys.stderr)
        return 1

    print(f"artifact built: {out}")
    if args.zip:
        archive = shutil.make_archive(str(out), "zip", root_dir=out)
        print(f"archive: {archive}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
