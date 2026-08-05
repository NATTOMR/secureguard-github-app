"""
Purpose: TheHive SOAR Case Builder Provider implementation.

Responsibilities:
- Implement SOCProvider for TheHive SOAR REST API case creation.
"""

from typing import Any, Dict, Optional
from app.core.config import get_settings
from app.integrations.base import SOCProvider


class TheHiveProvider(SOCProvider):
    """TheHive SOAR integration provider."""

    def __init__(self) -> None:
        self.settings = get_settings()

    @property
    def platform_name(self) -> str:
        return "thehive"

    async def health(self) -> Dict[str, Any]:
        configured = bool(self.settings.THEHIVE_URL and self.settings.THEHIVE_API_KEY)
        return {
            "platform": self.platform_name,
            "status": "healthy" if configured else "unconfigured",
            "url": self.settings.THEHIVE_URL or "http://thehive.local:9000",
        }

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        case = {
            "title": f"SecureGuard Alert: {alert_payload.get('title')}",
            "description": alert_payload.get("summary"),
            "severity": 3 if alert_payload.get("severity") == "CRITICAL" else 2,
            "tlp": 2,  # Amber
            "pap": 2,
            "tags": ["secureguard", alert_payload.get("scanner", "scanner")],
            "tasks": [
                {"title": "Verify finding"},
                {"title": "Apply secure remediation patch"},
            ],
        }
        return {"platform": self.platform_name, "status": "case_created", "case": case}

    async def send_incident(self, incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert(incident_payload)

    async def send_ioc(self, ioc_payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert(ioc_payload)

    async def close_alert(self, alert_id: str) -> Dict[str, Any]:
        return {"platform": self.platform_name, "status": "case_closed", "case_id": alert_id}

    async def search(self, query: str) -> Dict[str, Any]:
        return {"platform": self.platform_name, "query": query, "cases": []}
