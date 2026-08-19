"""Dashboard API authentication and browser-boundary regression tests."""

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from dashboard.app import app


TOKEN = "test-dashboard-admin-token-32-characters-minimum"


def test_api_fails_closed_without_strong_token(monkeypatch):
    monkeypatch.delenv("AES_DASHBOARD_TOKEN", raising=False)
    response = TestClient(app).get("/api/state")
    assert response.status_code == 503


def test_api_rejects_missing_or_wrong_token(monkeypatch):
    monkeypatch.setenv("AES_DASHBOARD_TOKEN", TOKEN)
    client = TestClient(app)
    assert client.get("/api/state").status_code == 401
    assert client.get("/api/state", headers={"X-AES-Admin-Token": "wrong"}).status_code == 401


def test_api_accepts_bound_token_and_rejects_unknown_origin(monkeypatch):
    monkeypatch.setenv("AES_DASHBOARD_TOKEN", TOKEN)
    client = TestClient(app)
    assert client.get("/api/state", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
    response = client.get(
        "/api/state",
        headers={"X-AES-Admin-Token": TOKEN, "Origin": "https://attacker.invalid"},
    )
    assert response.status_code == 403


def test_security_headers_are_applied():
    response = TestClient(app).get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
