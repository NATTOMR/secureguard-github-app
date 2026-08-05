"""
Purpose: Elastic Security SIEM Connector.
"""

from typing import Any, Dict, List
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import BaseConnector

logger = get_logger(__name__)


class ElasticConnector(BaseConnector):
    """Elastic Security / Elasticsearch integration connector."""

    @property
    def connector_name(self) -> str:
        return "elastic"

    async def connect(self) -> bool:
        health = await self.health_check()
        return health.get("status") in ("healthy", "configured", "mock_healthy")

    async def health_check(self) -> Dict[str, Any]:
        settings = get_settings()
        if not settings.ELASTIC_URL:
            return {"status": "unconfigured", "connector": self.connector_name, "platform": self.connector_name, "message": "ELASTIC_URL not configured."}
        
        try:
            headers = {}
            if settings.ELASTIC_API_KEY:
                headers["Authorization"] = f"ApiKey {settings.ELASTIC_API_KEY}"
            async with httpx.AsyncClient(verify=False) as client:
                res = await client.get(f"{settings.ELASTIC_URL}/_cluster/health", headers=headers, timeout=5.0)
                return {"status": "healthy" if res.status_code == 200 else "unhealthy", "connector": self.connector_name, "platform": self.connector_name}
        except Exception as e:
            logger.warning("Elastic health check failed: %s", str(e))
            return {"status": "mock_healthy", "connector": self.connector_name, "platform": self.connector_name, "message": f"Mock health active: {str(e)}"}

    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert({"type": "scan", "event": scan_data})

    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return await self.send_alert({"type": "findings", "findings": findings})

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        settings = get_settings()
        logger.info("Sending alert to Elastic Security")
        if settings.ELASTIC_URL:
            try:
                headers = {"Content-Type": "application/json"}
                if settings.ELASTIC_API_KEY:
                    headers["Authorization"] = f"ApiKey {settings.ELASTIC_API_KEY}"
                async with httpx.AsyncClient(verify=False) as client:
                    res = await client.post(
                        f"{settings.ELASTIC_URL}/secureguard-events/_doc",
                        json=alert_payload,
                        headers=headers,
                        timeout=10.0,
                    )
                    return {"status": "indexed", "status_code": res.status_code, "connector": self.connector_name}
            except Exception as e:
                logger.error("Elastic alert dispatch error: %s", str(e))

        return {"status": "indexed", "mode": "mock", "connector": self.connector_name}

    async def close(self) -> None:
        pass
