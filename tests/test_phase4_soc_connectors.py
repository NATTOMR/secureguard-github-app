"""
Purpose: Automated unit tests for Phase 4 Connectors & ConnectorManager.
"""

from unittest.mock import AsyncMock, patch
import pytest

from app.integrations.connector_manager import ConnectorManager
from app.integrations.connectors import (
    DiscordConnector,
    ElasticConnector,
    MISPConnector,
    SentinelConnector,
    SlackConnector,
    SplunkConnector,
    TeamsConnector,
    TheHiveConnector,
    WazuhConnector,
)


@pytest.mark.asyncio
async def test_connector_manager_discovery():
    """Test ConnectorManager auto-discovers all 9 connectors."""
    manager = ConnectorManager()
    assert len(manager.connectors) == 9
    assert "wazuh" in manager.connectors
    assert "splunk" in manager.connectors
    assert "sentinel" in manager.connectors
    assert "elastic" in manager.connectors
    assert "thehive" in manager.connectors
    assert "misp" in manager.connectors
    assert "slack" in manager.connectors
    assert "teams" in manager.connectors
    assert "discord" in manager.connectors


@pytest.mark.asyncio
async def test_connector_enable_disable():
    """Test enable/disable runtime toggles."""
    manager = ConnectorManager()
    assert manager.is_enabled("slack") is False

    manager.enable_connector("slack")
    assert manager.is_enabled("slack") is True

    manager.disable_connector("slack")
    assert manager.is_enabled("slack") is False


@pytest.mark.asyncio
async def test_connectors_health_check_defaults():
    """Test health check default behavior when unconfigured."""
    connectors = [
        WazuhConnector(),
        SplunkConnector(),
        SentinelConnector(),
        ElasticConnector(),
        TheHiveConnector(),
        MISPConnector(),
        SlackConnector(),
        TeamsConnector(),
        DiscordConnector(),
    ]
    for c in connectors:
        health = await c.health_check()
        assert "status" in health
        assert health["connector"] == c.connector_name


@pytest.mark.asyncio
async def test_connectors_send_alert():
    """Test send_alert execution across all connectors."""
    alert_payload = {
        "title": "AWS Secret Exposed",
        "severity": "CRITICAL",
        "repository": "NATTOMR/secureguard-github-app",
        "rule": "gitleaks-aws-key",
    }
    connectors = [
        WazuhConnector(),
        SplunkConnector(),
        SentinelConnector(),
        ElasticConnector(),
        TheHiveConnector(),
        MISPConnector(),
        SlackConnector(),
        TeamsConnector(),
        DiscordConnector(),
    ]
    for c in connectors:
        res = await c.send_alert(alert_payload)
        assert "status" in res
        assert res["connector"] == c.connector_name


@pytest.mark.asyncio
async def test_connector_manager_dispatch_scan_completed():
    """Test dispatch_scan_completed distributes event to enabled connectors."""
    manager = ConnectorManager()
    scan_data = {
        "scan_id": "scan-xyz",
        "repository": "NATTOMR/secureguard-github-app",
        "commit_sha": "abc1234",
        "total_findings": 2,
    }
    res = await manager.dispatch_scan_completed(scan_data)
    assert len(res) == 9
