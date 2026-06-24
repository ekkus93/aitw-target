"""Build the Round 2 intake artifact from an allow-list (build tool — not shipped).

Produces a minimal artifact directory matching the current intake contract:

    dist/round2-submission/
      deployment.yaml          # exact accepted schema (name / provider / declared_secrets)
      provider.py              # root shim exporting DEPLOYMENT
      src/agent_deployment/    # trimmed support package (adapter + reused policy modules)

It deliberately does NOT copy the working tree — only the explicit module allow-list below — and
never includes the underlying runtime fork, the rich manifest, the bulletin schema, operator/packet
docs, attacks, scenarios, caches, evidence, or the dev/build tools (this module, the artifact scan,
packaging, preflight, evidence). After building, ``export()`` runs the Round 2 artifact scan and
refuses to return an artifact that is not clean.

This is the current submission exporter. The legacy host-plugin exporter (``packaging``) remains for
development/evidence only and must not be used for the Round 2 submission.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from agent_deployment.round2_artifact_scan import scan_round2_artifact

REPO_ROOT = Path(__file__).resolve().parents[2]

# Support-package modules that ship. Only the adapter and the policy modules it transitively imports
# are included; dev/build tools (packaging, artifact scans, evidence, preflight, reset, run_local),
# the legacy provider, the bulletin interface, metadata, and the README are intentionally excluded.
SHIP_MODULES = (
    "adapter.py",
    "registry.py",
    "policy.py",
    "policy_engine.py",
    "memory_policy.py",
    "external_effects.py",
    "sanitizer.py",
    "scanner.py",
    "telemetry.py",
)

# Exact accepted manifest. No comments, no extra keys (the intake loader rejects extra fields).
_DEPLOYMENT_YAML = "name: defense\nprovider: provider:DEPLOYMENT\ndeclared_secrets: []\n"

# Root provider shim: puts the artifact-local src on sys.path and re-exports DEPLOYMENT. No packet
# text, attestation, labels, token values, or commentary.
_PROVIDER_PY = '''\
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agent_deployment.adapter import DEPLOYMENT

__all__ = ["DEPLOYMENT"]
'''

# Trimmed package init: the submitted package must not import the legacy RunHooks provider.
_INIT_PY = '"""Provider support package."""\n\n__all__ = []\n'


def build_round2_artifact(out_dir: str | Path, *, repo_root: str | Path | None = None) -> Path:
    """Assemble the Round 2 artifact tree at ``out_dir`` (replacing it if it exists)."""
    repo_root = Path(repo_root or REPO_ROOT)
    out = Path(out_dir)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    (out / "deployment.yaml").write_text(_DEPLOYMENT_YAML, encoding="utf-8")
    (out / "provider.py").write_text(_PROVIDER_PY, encoding="utf-8")

    pkg = out / "src" / "agent_deployment"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(_INIT_PY, encoding="utf-8")
    for module in SHIP_MODULES:
        shutil.copy2(repo_root / "src" / "agent_deployment" / module, pkg / module)

    return out


def export(out_dir: str | Path, *, repo_root: str | Path | None = None, verify: bool = True) -> Path:
    """Build the artifact and, unless ``verify`` is False, fail if the scan finds anything."""
    out = build_round2_artifact(out_dir, repo_root=repo_root)
    if verify:
        findings = scan_round2_artifact(out)
        if findings:
            detail = "; ".join(f"[{f.kind}] {f.path}: {f.detail}" for f in findings[:20])
            raise RuntimeError(f"round2 artifact failed scan: {detail}")
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Export the minimal Round 2 intake artifact.")
    parser.add_argument("--out", default="dist/round2-submission", help="output directory")
    parser.add_argument("--no-verify", action="store_true", help="skip the artifact scan")
    args = parser.parse_args(argv)

    try:
        out = export(args.out, verify=not args.no_verify)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"export failed: {exc}", file=sys.stderr)
        return 1

    print(f"round2 artifact built: {out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
