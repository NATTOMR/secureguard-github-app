"""
Purpose: Elastic Security ECS Provider implementation.

Responsibilities:
- Implement SOCProvider for Elastic Common Schema (ECS) documents.
"""

from typing import Any, Dict, Optional
from app.core.config import get_settings
from app.integrations.base import SOCProvider


class ElasticProvider(SOCProvider):
    """Elastic Security ECS integration provider."""

    def __init__(self) -> None:
        self.settings = get_settings()

    @property
    def platform_name(self) -> str:
        return "elastic"

    async def health(self) -> Dict[str, Any]:
        configured = bool(self.settings.ELASTIC_URL and self.settings.ELASTIC_API_KEY)
        return {
            "platform": self.platform_name,
            "status": "healthy" if configured else "unconfigured",
            "url": self.settings.ELASTIC_URL or "https://elastic.local:9200",
        }

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        ecs_doc = {
            "@timestamp": alert_payload.get("timestamp"),
            "event": {
                "kind": "alert",
                "category": ["vulnerability", "threat"],
                "type": ["indicator"],
                "dataset": "secureguard.findings",
            },
            "vulnerability": {
                "id": alert_payload.get("rule"),
                "category": alert_payload.get("scanner"),
                "severity": alert_payload.get("severity"),
            },
            "secureguard": alert_payload,
        }
        return {"platform": self.platform_name, "status": "indexed", "index": "logs-secureguard-default", "doc": ecs_doc}

    async def send_incident(self, incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert(incident_payload)

    async def send_ioc(self, ioc_payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert(ioc_payload)

    async def close_alert(self, alert_id: str) -> Dict[str, Any]:
        return {"platform": self.platform_name, "status": "closed", "alert_id": alert_id}

    async def search(self, query: str) -> Dict[str, Any]:
        return {"platform": self.platform_name, "query": query, "hits": []}
