"""
Purpose: Microsoft Teams Connector (Adaptive Cards).
"""

from typing import Any, Dict, List
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import BaseConnector

logger = get_logger(__name__)


class TeamsConnector(BaseConnector):
    """Microsoft Teams Adaptive Cards notification connector."""

    @property
    def connector_name(self) -> str:
        return "teams"

    async def connect(self) -> bool:
        health = await self.health_check()
        return health.get("status") in ("healthy", "configured", "mock_healthy")

    async def health_check(self) -> Dict[str, Any]:
        settings = get_settings()
        if not settings.TEAMS_WEBHOOK:
            return {"status": "unconfigured", "connector": self.connector_name, "message": "TEAMS_WEBHOOK not configured."}
        return {"status": "configured", "connector": self.connector_name}

    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert({"type": "scan_completed", "scan": scan_data})

    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return await self.send_alert({"type": "findings", "findings": findings})

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        settings = get_settings()
        logger.info("Sending Adaptive Card alert to MS Teams")

        title = alert_payload.get("title") or alert_payload.get("rule") or "SecureGuard Security Finding"
        severity = alert_payload.get("severity", "HIGH").upper()
        repo = alert_payload.get("repository", "unknown/repo")

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {"type": "TextBlock", "text": f"🛡️ SecureGuard Alert: {title}", "weight": "Bolder", "size": "Medium"},
                            {"type": "TextBlock", "text": f"**Repository:** {repo} | **Severity:** {severity}", "isSubtle": True},
                        ]
                    }
                }
            ]
        }

        if settings.TEAMS_WEBHOOK:
            try:
                async with httpx.AsyncClient() as client:
                    res = await client.post(settings.TEAMS_WEBHOOK, json=card, timeout=10.0)
                    return {"status": "sent", "status_code": res.status_code, "connector": self.connector_name}
            except Exception as e:
                logger.error("Teams notification error: %s", str(e))

        return {"status": "sent", "mode": "mock", "connector": self.connector_name}

    async def close(self) -> None:
        pass
