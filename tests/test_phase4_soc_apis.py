"""
Purpose: Automated tests for Phase 4 REST APIs under /api/integrations/*.
"""

import pytest


def test_list_integrations_endpoint(client):
    """Test GET /api/integrations endpoint."""
    res = client.get("/api/integrations")
    assert res.status_code == 200
    data = res.json()
    assert "wazuh" in data
    assert "slack" in data


def test_get_integrations_events_endpoint(client):
    """Test GET /api/integrations/events endpoint."""
    res = client.get("/api/integrations/events")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)


def test_test_connector_endpoint(client):
    """Test POST /api/integrations/test endpoint."""
    res = client.post("/api/integrations/test", json={"connector": "slack"})
    assert res.status_code == 200
    data = res.json()
    assert data["connector"] == "slack"
    assert "health" in data


def test_enable_disable_connector_endpoint(client):
    """Test POST /api/integrations/enable and /disable endpoints."""
    res = client.post("/api/integrations/enable", json={"connector": "discord"})
    assert res.status_code == 200
    assert res.json()["enabled"] is True

    res = client.post("/api/integrations/disable", json={"connector": "discord"})
    assert res.status_code == 200
    assert res.json()["enabled"] is False


def test_platform_specific_endpoints(client):
    """Test platform-specific endpoints (Wazuh, Splunk, Sentinel, Elastic, TheHive, MISP, Slack, Teams, Discord)."""
    endpoints = [
        ("/api/integrations/wazuh/send", {"title": "Test"}),
        ("/api/integrations/splunk/send", {"title": "Test"}),
        ("/api/integrations/sentinel/send", {"title": "Test"}),
        ("/api/integrations/elastic/send", {"title": "Test"}),
        ("/api/integrations/thehive/alert", {"title": "Test"}),
        ("/api/integrations/misp/event", {"title": "Test"}),
        ("/api/integrations/slack/test", {"title": "Test"}),
        ("/api/integrations/teams/test", {"title": "Test"}),
        ("/api/integrations/discord/test", {"title": "Test"}),
    ]

    for ep, payload in endpoints:
        res = client.post(ep, json=payload)
        assert res.status_code == 200
        assert "status" in res.json()
