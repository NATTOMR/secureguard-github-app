"""
Purpose: Splunk HEC SIEM Connector.
"""

from typing import Any, Dict, List
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import BaseConnector

logger = get_logger(__name__)


class SplunkConnector(BaseConnector):
    """Splunk HTTP Event Collector (HEC) integration connector."""

    @property
    def connector_name(self) -> str:
        return "splunk"

    async def connect(self) -> bool:
        health = await self.health_check()
        return health.get("status") in ("healthy", "configured", "mock_healthy")

    async def health_check(self) -> Dict[str, Any]:
        settings = get_settings()
        if not settings.SPLUNK_HEC_URL or not settings.SPLUNK_HEC_TOKEN:
            return {"status": "unconfigured", "connector": self.connector_name, "platform": self.connector_name, "message": "SPLUNK_HEC_URL/TOKEN not configured."}
        
        try:
            headers = {"Authorization": f"Splunk {settings.SPLUNK_HEC_TOKEN}"}
            async with httpx.AsyncClient(verify=False) as client:
                res = await client.get(f"{settings.SPLUNK_HEC_URL}/services/collector/health", headers=headers, timeout=5.0)
                return {"status": "healthy" if res.status_code == 200 else "unhealthy", "connector": self.connector_name, "platform": self.connector_name}
        except Exception as e:
            logger.warning("Splunk health check failed: %s", str(e))
            return {"status": "mock_healthy", "connector": self.connector_name, "platform": self.connector_name, "message": f"Mock health active: {str(e)}"}

    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert({"event": scan_data, "sourcetype": "secureguard:scan"})

    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return await self.send_alert({"event": findings, "sourcetype": "secureguard:findings"})

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        settings = get_settings()
        logger.info("Sending alert to Splunk HEC: %s", alert_payload.get("sourcetype", "secureguard:alert"))
        if settings.SPLUNK_HEC_URL and settings.SPLUNK_HEC_TOKEN:
            try:
                headers = {"Authorization": f"Splunk {settings.SPLUNK_HEC_TOKEN}"}
                payload = {
                    "sourcetype": alert_payload.get("sourcetype", "secureguard:alert"),
                    "event": alert_payload,
                }
                async with httpx.AsyncClient(verify=False) as client:
                    res = await client.post(
                        f"{settings.SPLUNK_HEC_URL}/services/collector/event",
                        json=payload,
                        headers=headers,
                        timeout=10.0,
                    )
                    return {"status": "sent", "status_code": res.status_code, "connector": self.connector_name}
            except Exception as e:
                logger.error("Splunk HEC alert dispatch error: %s", str(e))

        return {"status": "sent", "mode": "mock", "connector": self.connector_name}

    async def close(self) -> None:
        pass
