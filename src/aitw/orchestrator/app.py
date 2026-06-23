"""Minimal FastAPI orchestrator/status surface.

Conventional, slightly-too-trusting defaults on purpose: permissive CORS,
verbose errors (debug=True), and the fail-open admin auth from admin.py. This surface exists
so the orchestrator/admin secondary attack surface is reachable; it is not a product.

fastapi is imported here; the core test suite does not require it (it tests the harness
directly). `uvicorn src/aitw/orchestrator/app.py` style isn't used — run with:
    uvicorn aitw.orchestrator.app:app --reload
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware

from aitw.orchestrator.admin import check_admin

app = FastAPI(title="Agents in the Wild — orchestrator (naive target)", debug=True)

# Permissive CORS — naive default. Do not tighten here; that's the blue team's call.
# Reachability note (baseline reconciliation): allow_origins=["*"] WITH allow_credentials=True is
# rejected by browsers (the Fetch spec forbids the wildcard with credentials), so the credentialed
# cross-origin read is reachable from NON-browser / programmatic HTTP clients, not from a browser.
# The misconfiguration signal stands; the exploit path is non-browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


def _auth(authorization: str | None = Header(default=None)) -> dict:
    return check_admin(authorization)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/status")
def status(auth: dict = Depends(_auth)) -> dict:
    from aitw.scenarios import scenario_names

    return {
        "auth": auth,  # note: always granted (fail-open) — see admin.py
        "scenarios": scenario_names(),
        "note": "naive status surface; auth is fail-open by design",
    }
