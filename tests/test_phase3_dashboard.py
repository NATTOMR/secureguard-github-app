"""
Purpose: Automated tests for Phase 3 Dashboard REST APIs (/api/dashboard/*).
"""

import pytest


def test_get_dashboard_history(client):
    """Test GET /api/dashboard/history timeline endpoint."""
    res = client.get("/api/dashboard/history")
    assert res.status_code == 200
    data = res.json()
    assert "scans" in data
    assert "total_count" in data


def test_get_dashboard_trends(client):
    """Test GET /api/dashboard/trends endpoint."""
    res = client.get("/api/dashboard/trends?weeks=4")
    assert res.status_code == 200
    data = res.json()
    assert "trend_data" in data
    assert data["weeks"] == 4


def test_get_dashboard_leaderboard(client):
    """Test GET /api/dashboard/leaderboard endpoint."""
    res = client.get("/api/dashboard/leaderboard")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


def test_get_common_vulnerabilities(client):
    """Test GET /api/dashboard/common-vulnerabilities endpoint."""
    res = client.get("/api/dashboard/common-vulnerabilities")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


def test_get_scanner_usage(client):
    """Test GET /api/dashboard/scanner-usage endpoint."""
    res = client.get("/api/dashboard/scanner-usage")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


def test_get_weekly_stats(client):
    """Test GET /api/dashboard/weekly-stats endpoint."""
    res = client.get("/api/dashboard/weekly-stats")
    assert res.status_code == 200
    data = res.json()
    assert "scans_this_week" in data
    assert "findings_this_week" in data
