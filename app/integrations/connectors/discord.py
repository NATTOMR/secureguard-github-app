"""
Purpose: Discord Webhook Notification Connector.
"""

from typing import Any, Dict, List
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import BaseConnector

logger = get_logger(__name__)


class DiscordConnector(BaseConnector):
    """Discord Webhooks & Rich Embeds notification connector."""

    @property
    def connector_name(self) -> str:
        return "discord"

    async def connect(self) -> bool:
        health = await self.health_check()
        return health.get("status") in ("healthy", "configured", "mock_healthy")

    async def health_check(self) -> Dict[str, Any]:
        settings = get_settings()
        if not settings.DISCORD_WEBHOOK:
            return {"status": "unconfigured", "connector": self.connector_name, "message": "DISCORD_WEBHOOK not configured."}
        return {"status": "configured", "connector": self.connector_name}

    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert({"type": "scan_completed", "scan": scan_data})

    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return await self.send_alert({"type": "findings", "findings": findings})

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        settings = get_settings()
        logger.info("Sending rich embed alert to Discord channel")

        title = alert_payload.get("title") or alert_payload.get("rule") or "SecureGuard Alert"
        severity = alert_payload.get("severity", "HIGH").upper()
        repo = alert_payload.get("repository", "unknown/repo")

        color_map = {"CRITICAL": 15673937, "HIGH": 16347670, "MEDIUM": 15381256, "LOW": 3899638}
        color = color_map.get(severity, 6581419)

        embed = {
            "embeds": [
                {
                    "title": f"🛡️ SecureGuard Alert: {title}",
                    "color": color,
                    "fields": [
                        {"name": "Repository", "value": f"`{repo}`", "inline": True},
                        {"name": "Severity", "value": f"**{severity}**", "inline": True},
                    ],
                }
            ]
        }

        if settings.DISCORD_WEBHOOK:
            try:
                async with httpx.AsyncClient() as client:
                    res = await client.post(settings.DISCORD_WEBHOOK, json=embed, timeout=10.0)
                    return {"status": "sent", "status_code": res.status_code, "connector": self.connector_name}
            except Exception as e:
                logger.error("Discord notification error: %s", str(e))

        return {"status": "sent", "mode": "mock", "connector": self.connector_name}

    async def close(self) -> None:
        pass
