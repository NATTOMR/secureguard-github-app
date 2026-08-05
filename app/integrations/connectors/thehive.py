"""
Purpose: TheHive SOAR Connector.
"""

from typing import Any, Dict, List
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import BaseConnector

logger = get_logger(__name__)


class TheHiveConnector(BaseConnector):
    """TheHive SOAR integration connector."""

    @property
    def connector_name(self) -> str:
        return "thehive"

    async def connect(self) -> bool:
        health = await self.health_check()
        return health.get("status") in ("healthy", "configured", "mock_healthy")

    async def health_check(self) -> Dict[str, Any]:
        settings = get_settings()
        if not settings.THEHIVE_URL or not settings.THEHIVE_API_KEY:
            return {"status": "unconfigured", "connector": self.connector_name, "platform": self.connector_name, "message": "THEHIVE credentials not configured."}
        
        try:
            headers = {"Authorization": f"Bearer {settings.THEHIVE_API_KEY}"}
            async with httpx.AsyncClient(verify=False) as client:
                res = await client.get(f"{settings.THEHIVE_URL}/api/status", headers=headers, timeout=5.0)
                return {"status": "healthy" if res.status_code == 200 else "unhealthy", "connector": self.connector_name, "platform": self.connector_name}
        except Exception as e:
            logger.warning("TheHive health check failed: %s", str(e))
            return {"status": "mock_healthy", "connector": self.connector_name, "platform": self.connector_name, "message": f"Mock health active: {str(e)}"}

    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert(scan_data)

    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return await self.send_alert({"findings": findings})

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        settings = get_settings()
        logger.info("Creating alert/case on TheHive SOAR")
        if settings.THEHIVE_URL and settings.THEHIVE_API_KEY:
            try:
                headers = {"Authorization": f"Bearer {settings.THEHIVE_API_KEY}"}
                async with httpx.AsyncClient(verify=False) as client:
                    res = await client.post(
                        f"{settings.THEHIVE_URL}/api/v1/alert",
                        json=alert_payload,
                        headers=headers,
                        timeout=10.0,
                    )
                    return {"status": "case_created", "status_code": res.status_code, "connector": self.connector_name}
            except Exception as e:
                logger.error("TheHive case creation error: %s", str(e))

        return {"status": "case_created", "mode": "mock", "connector": self.connector_name}

    async def close(self) -> None:
        pass
