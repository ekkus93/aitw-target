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
import os
import shutil
import subprocess
import sys
from pathlib import Path

from agent_deployment.round2_artifact_scan import scan_round2_artifact

REPO_ROOT = Path(__file__).resolve().parents[2]

# Status strings for the host-layout import check (never a silent false PASS).
IMPORT_VERIFIED = "verified"
IMPORT_SKIPPED = "skipped"

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
    "limits.py",
    "registered_secrets.py",
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


def _default_host_src(repo_root: Path) -> Path | None:
    """The development host runtime, when present: ``repo_root/src`` if it carries ``aitw``."""
    src = repo_root / "src"
    return src if (src / "aitw").is_dir() else None


def verify_import(artifact_root: str | Path, *, host_src: str | Path | None = None) -> str:
    """Host-layout import-check the generated ``provider.py`` in a CLEAN subprocess.

    Runs in a fresh interpreter with ``PYTHONPATH`` scrubbed and ``sys.path`` set to
    ``[artifact/src, host_src]`` so ``agent_deployment`` is loaded from the GENERATED artifact (not
    the development repo) while ``aitw`` resolves from the host runtime. Asserts ``DEPLOYMENT.name ==
    "defense"`` and that ``wrap_store`` / ``task_registry`` exist.

    Returns ``IMPORT_VERIFIED`` on success, ``IMPORT_SKIPPED`` when no host runtime is available
    (never a false PASS). Raises ``RuntimeError`` if a host runtime is available but the import fails.
    """
    artifact_root = Path(artifact_root).resolve()
    if host_src is None:
        host_src = _default_host_src(REPO_ROOT)
    if host_src is None or not Path(host_src).is_dir():
        return IMPORT_SKIPPED
    host_src = Path(host_src).resolve()

    code = (
        "import importlib.util, sys\n"
        "root, host = sys.argv[1], sys.argv[2]\n"
        "sys.path[:0] = [root + '/src', host]\n"  # artifact src FIRST, then host runtime
        "spec = importlib.util.spec_from_file_location('r2_provider', root + '/provider.py')\n"
        "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
        "d = m.DEPLOYMENT\n"
        "assert d.name == 'defense', 'unexpected DEPLOYMENT.name'\n"
        "for meth in ('wrap_store', 'task_registry', 'posture_registry', 'make_scanner', 'make_broker'):\n"
        "    assert hasattr(d, meth), 'missing ' + meth\n"
        "sc = d.make_scanner()\n"
        "assert hasattr(sc, 'register') and hasattr(sc.scan('x'), 'redacted'), 'scanner contract'\n"
        "bk = d.make_broker(scanner=sc, model_key='m', tool_backing_secret='t')\n"
        "assert bk is not None and hasattr(bk, 'issue_tool_credential') and hasattr(bk, 'is_valid'), 'broker contract'\n"
        "cr = bk.issue_tool_credential('tenant_a')\n"
        "assert hasattr(cr, 'ttl_seconds') and bk.is_valid(cr), 'credential contract'\n"
        "print('IMPORT_OK')\n"
    )
    # Scrub PYTHONPATH (so the dev repo is not on the path) and disable bytecode writing (so the
    # import does not leave a __pycache__ inside the clean artifact).
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-B", "-c", code, str(artifact_root), str(host_src)],
        capture_output=True,
        text=True,
        env=env,
    )
    if proc.returncode != 0 or "IMPORT_OK" not in proc.stdout:
        raise RuntimeError(f"host-layout import check failed: {(proc.stderr or proc.stdout).strip()[:500]}")
    return IMPORT_VERIFIED


def export(
    out_dir: str | Path,
    *,
    repo_root: str | Path | None = None,
    verify: bool = True,
    import_check: bool = True,
    host_src: str | Path | None = None,
) -> Path:
    """Build the artifact, fail the scan (unless ``verify`` is False), and host-layout import-check it.

    The import check (unless ``import_check`` is False) runs in a clean subprocess and raises on a
    genuine import failure; it returns a skipped status when no host runtime is available.
    """
    out = build_round2_artifact(out_dir, repo_root=repo_root)
    if verify:
        findings = scan_round2_artifact(out)
        if findings:
            detail = "; ".join(f"[{f.kind}] {f.path}: {f.detail}" for f in findings[:20])
            raise RuntimeError(f"round2 artifact failed scan: {detail}")
    if import_check:
        verify_import(out, host_src=host_src)  # raises on failure; skip status surfaced by main()
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Export the minimal Round 2 intake artifact.")
    parser.add_argument("--out", default="dist/round2-submission", help="output directory")
    parser.add_argument("--no-verify", action="store_true", help="skip the artifact scan")
    parser.add_argument("--no-import-check", action="store_true", help="skip the host-layout import check")
    parser.add_argument("--host-src", default=None, help="host runtime src dir for the import check")
    args = parser.parse_args(argv)

    try:
        out = build_round2_artifact(args.out)
        if not args.no_verify:
            findings = scan_round2_artifact(out)
            if findings:
                detail = "; ".join(f"[{f.kind}] {f.path}: {f.detail}" for f in findings[:20])
                raise RuntimeError(f"round2 artifact failed scan: {detail}")
        status = IMPORT_SKIPPED
        if not args.no_import_check:
            status = verify_import(out, host_src=args.host_src)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"export failed: {exc}", file=sys.stderr)
        return 1

    print(f"round2 artifact built: {out}")
    if args.no_import_check:
        print("host-layout import check: skipped (--no-import-check)")
    elif status == IMPORT_VERIFIED:
        print("host-layout import check: verified (DEPLOYMENT.name == defense)")
    else:
        print("host-layout import check: SKIPPED — no host runtime available, NOT verified")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
