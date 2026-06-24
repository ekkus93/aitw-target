"""Dependency / export metadata for reproducibility (build tool — not shipped).

Records the Python version and the resolved versions of the third-party packages the runtime relies
on, so an event/review run can reproduce the dependency set. Written into the exported artifact as
``metadata.json`` by the packaging step. Only third-party distributions are recorded — never the
local package name — so the metadata carries no project label.
"""

from __future__ import annotations

import json
import os
import platform
from importlib import metadata as _im
from pathlib import Path

# Third-party distributions whose versions are worth pinning for reproducibility. The local
# deployment package is deliberately excluded (its name is not recorded).
TRACKED_DISTRIBUTIONS = ("anthropic", "PyYAML", "pydantic", "fastapi", "uvicorn")


def dependency_metadata() -> dict:
    """Return {python_version, packages: {dist: version}} for the tracked distributions present.

    Also records whether a host lure registry is CONFIGURED — explicitly scoped to the build
    environment only, so it is never mistaken for the runtime/grader status (that lives in the run
    telemetry). No raw lure values are recorded.
    """
    packages: dict = {}
    for dist in TRACKED_DISTRIBUTIONS:
        try:
            packages[dist] = _im.version(dist)
        except _im.PackageNotFoundError:
            continue
    return {
        "schema": "dependency-metadata/1",
        "python_version": platform.python_version(),
        "packages": packages,
        "host_lure_registry_configured_at_build": bool(os.environ.get("HOST_LURE_REGISTRY")),
        "host_lure_registry_status_scope": "build_environment_only",
    }


def write_metadata(path: str | Path) -> Path:
    """Write the dependency metadata as JSON to ``path`` and return it."""
    p = Path(path)
    p.write_text(json.dumps(dependency_metadata(), indent=2, sort_keys=True), encoding="utf-8")
    return p
