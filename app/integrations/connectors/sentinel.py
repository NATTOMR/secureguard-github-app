"""
Purpose: Microsoft Sentinel / Azure Log Analytics Connector.
"""

from typing import Any, Dict, List
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import BaseConnector

logger = get_logger(__name__)


class SentinelConnector(BaseConnector):
    """Microsoft Sentinel / Azure Log Analytics integration connector."""

    @property
    def connector_name(self) -> str:
        return "sentinel"

    async def connect(self) -> bool:
        health = await self.health_check()
        return health.get("status") in ("healthy", "configured", "mock_healthy")

    async def health_check(self) -> Dict[str, Any]:
        settings = get_settings()
        if not settings.SENTINEL_WORKSPACE_ID or not settings.SENTINEL_SHARED_KEY:
            return {"status": "unconfigured", "connector": self.connector_name, "platform": self.connector_name, "message": "SENTINEL credentials not configured."}
        
        return {"status": "configured", "connector": self.connector_name, "platform": self.connector_name}

    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert({"LogType": "SecureGuard_Scans", "data": scan_data})

    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return await self.send_alert({"LogType": "SecureGuard_Findings", "data": findings})

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        settings = get_settings()
        logger.info("Sending alert to Microsoft Sentinel")
        if settings.SENTINEL_WORKSPACE_ID and settings.SENTINEL_SHARED_KEY:
            try:
                uri = f"https://{settings.SENTINEL_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
                headers = {
                    "content-type": "application/json",
                    "Log-Type": "SecureGuard_SecurityEvents",
                }
                async with httpx.AsyncClient() as client:
                    res = await client.post(uri, json=alert_payload, headers=headers, timeout=10.0)
                    return {"status": "sent", "status_code": res.status_code, "connector": self.connector_name}
            except Exception as e:
                logger.error("Sentinel alert dispatch error: %s", str(e))

        return {"status": "sent", "mode": "mock", "connector": self.connector_name}

    async def close(self) -> None:
        pass
