"""
Purpose: Test suite for Dashboard REST APIs (/api/*).

Responsibilities:
- Test GET /api/dashboard overview metrics endpoint.
- Test GET /api/repositories listing endpoint.
- Test GET /api/scans history endpoint.
- Test GET /api/findings filterable findings endpoint.
- Test GET /api/events audit log endpoint.

Dependencies:
- pytest
- app.main.create_app

Usage:
    pytest tests/test_dashboard_api.py -v
"""

import pytest


def test_get_dashboard_overview_endpoint(client):
    """Test GET /api/dashboard returns overview metrics."""
    res = client.get("/api/dashboard")
    assert res.status_code == 200
    data = res.json()
    assert "total_repositories" in data
    assert "total_scans" in data
    assert "critical_findings" in data
    assert "latest_scans" in data


def test_get_repositories_endpoint(client):
    """Test GET /api/repositories endpoint."""
    res = client.get("/api/repositories")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, (list, dict))


def test_get_scans_endpoint(client):
    """Test GET /api/scans endpoint."""
    res = client.get("/api/scans")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


def test_get_findings_endpoint(client):
    """Test GET /api/findings endpoint with severity filter."""
    res = client.get("/api/findings?severity=CRITICAL")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


def test_get_events_endpoint(client):
    """Test GET /api/events endpoint."""
    res = client.get("/api/events")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


def test_render_dashboard_ui(client):
    """Test GET /dashboard renders HTML UI."""
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "SecureGuard" in res.text
