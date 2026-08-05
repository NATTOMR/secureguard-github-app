"""
Purpose: Test suite for SOC Integration Platform.

Responsibilities:
- Test Wazuh, Splunk, Elastic, Sentinel, TheHive, MISP providers.
- Test SOCIntegrationManager dispatching and health aggregation.
- Test /api/integrations/* REST endpoints.

Dependencies:
- pytest
- app.integrations.manager.SOCIntegrationManager

Usage:
    pytest tests/test_soc_integrations.py -v
"""

import pytest
from app.integrations.manager import SOCIntegrationManager


@pytest.mark.asyncio
async def test_soc_manager_health():
    """Test SOCIntegrationManager aggregates health for all 6 platforms."""
    manager = SOCIntegrationManager()
    statuses = await manager.get_all_health()
    assert "wazuh" in statuses
    assert "splunk" in statuses
    assert "elastic" in statuses
    assert "sentinel" in statuses
    assert "thehive" in statuses
    assert "misp" in statuses


@pytest.mark.asyncio
async def test_soc_manager_dispatch():
    """Test SOCIntegrationManager normalizes finding and dispatches alert."""
    manager = SOCIntegrationManager()
    finding = {
        "title": "Hardcoded AWS Key",
        "severity": "CRITICAL",
        "repository": "octocat/Hello-World",
        "scanner": "Gitleaks",
        "rule_id": "aws-access-key",
    }
    res = await manager.dispatch_alert(finding)
    assert "event" in res
    assert "dispatches" in res
    assert res["dispatches"]["wazuh"]["status"] == "sent"
    assert res["dispatches"]["splunk"]["status"] == "sent"
    assert res["dispatches"]["elastic"]["status"] == "indexed"
    assert res["dispatches"]["sentinel"]["status"] == "sent"
    assert res["dispatches"]["thehive"]["status"] == "case_created"
    assert res["dispatches"]["misp"]["status"] == "event_created"


def test_api_integrations_status(client):
    """Test GET /api/integrations/status endpoint."""
    res = client.get("/api/integrations/status")
    assert res.status_code == 200
    data = res.json()
    assert "wazuh" in data
    assert "splunk" in data
    assert "sentinel" in data


def test_api_integrations_individual_endpoints(client):
    """Test GET /api/integrations/{platform} status endpoints."""
    platforms = ["wazuh", "splunk", "elastic", "sentinel", "thehive", "misp"]
    for p in platforms:
        res = client.get(f"/api/integrations/{p}")
        assert res.status_code == 200
        data = res.json()
        assert data["platform"] == p


def test_api_integrations_dispatch(client):
    """Test POST /api/integrations/dispatch endpoint."""
    payload = {
        "title": "Unsafe eval usage",
        "severity": "HIGH",
        "repository": "octocat/Hello-World",
        "file": "app/main.py",
        "line": 42,
    }
    res = client.post("/api/integrations/dispatch", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "dispatches" in data
