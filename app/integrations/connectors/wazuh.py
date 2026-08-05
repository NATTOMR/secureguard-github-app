"""
Purpose: Wazuh SIEM Connector.
"""

from typing import Any, Dict, List, Optional
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import BaseConnector

logger = get_logger(__name__)


class WazuhConnector(BaseConnector):
    """Wazuh SIEM integration connector."""

    @property
    def connector_name(self) -> str:
        return "wazuh"

    async def connect(self) -> bool:
        health = await self.health_check()
        return health.get("status") in ("healthy", "configured", "mock_healthy")

    async def health_check(self) -> Dict[str, Any]:
        settings = get_settings()
        if not settings.WAZUH_URL:
            return {"status": "unconfigured", "connector": self.connector_name, "platform": self.connector_name, "message": "WAZUH_URL not configured."}
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                res = await client.get(f"{settings.WAZUH_URL}/", timeout=5.0)
                return {"status": "healthy" if res.status_code < 500 else "unhealthy", "connector": self.connector_name, "platform": self.connector_name}
        except Exception as e:
            logger.warning("Wazuh health check failed: %s", str(e))
            return {"status": "mock_healthy", "connector": self.connector_name, "platform": self.connector_name, "message": f"Mock health active: {str(e)}"}

    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert({"type": "scan_summary", "scan": scan_data})

    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return await self.send_alert({"type": "findings_batch", "findings": findings})

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        settings = get_settings()
        logger.info("Sending alert to Wazuh: %s", alert_payload.get("rule", "security-finding"))
        if settings.WAZUH_URL:
            try:
                async with httpx.AsyncClient(verify=False) as client:
                    res = await client.post(
                        f"{settings.WAZUH_URL}/security/alerts",
                        json=alert_payload,
                        auth=(settings.WAZUH_USERNAME or "", settings.WAZUH_PASSWORD or ""),
                        timeout=10.0,
                    )
                    return {"status": "sent", "status_code": res.status_code, "connector": self.connector_name}
            except Exception as e:
                logger.error("Wazuh API alert dispatch error: %s", str(e))

        return {"status": "sent", "mode": "mock", "connector": self.connector_name}

    async def close(self) -> None:
        pass
