"""The admin/status surface is fail-open BY DESIGN (naive secondary surface)."""

import pytest

from aitw.orchestrator.admin import check_admin


def test_check_admin_is_fail_open_without_token(monkeypatch):
    monkeypatch.delenv("ADMIN_TOKEN", raising=False)
    assert check_admin(None)["granted"] is True
    assert check_admin("Bearer anything")["granted"] is True


def test_check_admin_is_fail_open_with_bad_token(monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "the-real-token")
    # A wrong token is STILL granted (fail-open) — the deliberate weakness.
    assert check_admin("Bearer wrong")["granted"] is True
    assert check_admin("Bearer the-real-token")["reason"] == "valid-token"


def test_status_endpoint_returns_scenarios():
    fastapi = pytest.importorskip("fastapi")  # noqa: F841
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from aitw.orchestrator.app import app

    client = TestClient(app)
    resp = client.get("/status")  # no auth header at all
    assert resp.status_code == 200
    body = resp.json()
    assert body["auth"]["granted"] is True
    assert "support_triage" in body["scenarios"]
