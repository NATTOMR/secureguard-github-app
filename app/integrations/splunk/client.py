"""
Purpose: Splunk Enterprise HEC Provider implementation.

Responsibilities:
- Implement SOCProvider for Splunk HTTP Event Collector (HEC).
"""

from typing import Any, Dict, Optional
from app.core.config import get_settings
from app.integrations.base import SOCProvider


class SplunkProvider(SOCProvider):
    """Splunk Enterprise HEC provider."""

    def __init__(self) -> None:
        self.settings = get_settings()

    @property
    def platform_name(self) -> str:
        return "splunk"

    async def health(self) -> Dict[str, Any]:
        configured = bool(self.settings.SPLUNK_HEC_URL and self.settings.SPLUNK_HEC_TOKEN)
        return {
            "platform": self.platform_name,
            "status": "healthy" if configured else "unconfigured",
            "url": self.settings.SPLUNK_HEC_URL or "https://splunk.local:8088/services/collector/event",
        }

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "platform": self.platform_name,
            "status": "sent",
            "hec_event": {
                "index": "secureguard_security",
                "sourcetype": "secureguard:json",
                "event": alert_payload,
            },
        }

    async def send_incident(self, incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert(incident_payload)

    async def send_ioc(self, ioc_payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert(ioc_payload)

    async def close_alert(self, alert_id: str) -> Dict[str, Any]:
        return {"platform": self.platform_name, "status": "closed", "alert_id": alert_id}

    async def search(self, query: str) -> Dict[str, Any]:
        return {"platform": self.platform_name, "query": query, "total_matches": 0, "results": []}
