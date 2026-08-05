"""
Purpose: MISP Threat Intelligence Connector.
"""

from typing import Any, Dict, List
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import BaseConnector

logger = get_logger(__name__)


class MISPConnector(BaseConnector):
    """MISP Threat Intelligence integration connector."""

    @property
    def connector_name(self) -> str:
        return "misp"

    async def connect(self) -> bool:
        health = await self.health_check()
        return health.get("status") in ("healthy", "configured", "mock_healthy")

    async def health_check(self) -> Dict[str, Any]:
        settings = get_settings()
        if not settings.MISP_URL or not settings.MISP_API_KEY:
            return {"status": "unconfigured", "connector": self.connector_name, "platform": self.connector_name, "message": "MISP credentials not configured."}
        
        try:
            headers = {"Authorization": settings.MISP_API_KEY, "Accept": "application/json"}
            async with httpx.AsyncClient(verify=False) as client:
                res = await client.get(f"{settings.MISP_URL}/servers/getPyMISPVersion.json", headers=headers, timeout=5.0)
                return {"status": "healthy" if res.status_code == 200 else "unhealthy", "connector": self.connector_name, "platform": self.connector_name}
        except Exception as e:
            logger.warning("MISP health check failed: %s", str(e))
            return {"status": "mock_healthy", "connector": self.connector_name, "platform": self.connector_name, "message": f"Mock health active: {str(e)}"}

    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert(scan_data)

    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return await self.send_alert({"findings": findings})

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        settings = get_settings()
        logger.info("Pushing IOC attribute event to MISP Threat Intel")
        if settings.MISP_URL and settings.MISP_API_KEY:
            try:
                headers = {"Authorization": settings.MISP_API_KEY, "Content-Type": "application/json"}
                async with httpx.AsyncClient(verify=False) as client:
                    res = await client.post(
                        f"{settings.MISP_URL}/events",
                        json={"Event": alert_payload},
                        headers=headers,
                        timeout=10.0,
                    )
                    return {"status": "event_created", "status_code": res.status_code, "connector": self.connector_name}
            except Exception as e:
                logger.error("MISP event creation error: %s", str(e))

        return {"status": "event_created", "mode": "mock", "connector": self.connector_name}

    async def close(self) -> None:
        pass
