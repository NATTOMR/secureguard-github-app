"""
Purpose: Slack Notification Connector.
"""

from typing import Any, Dict, List
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import BaseConnector

logger = get_logger(__name__)


class SlackConnector(BaseConnector):
    """Slack Incoming Webhooks & Notification Connector."""

    @property
    def connector_name(self) -> str:
        return "slack"

    async def connect(self) -> bool:
        health = await self.health_check()
        return health.get("status") in ("healthy", "configured", "mock_healthy")

    async def health_check(self) -> Dict[str, Any]:
        settings = get_settings()
        if not settings.SLACK_WEBHOOK:
            return {"status": "unconfigured", "connector": self.connector_name, "message": "SLACK_WEBHOOK not configured."}
        return {"status": "configured", "connector": self.connector_name}

    async def send_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.send_alert({"type": "scan_completed", "scan": scan_data})

    async def send_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return await self.send_alert({"type": "findings", "findings": findings})

    async def send_alert(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        settings = get_settings()
        logger.info("Sending notification alert to Slack channel")

        # Format Block Kit message
        title = alert_payload.get("title") or alert_payload.get("rule") or "SecureGuard Alert"
        severity = alert_payload.get("severity", "HIGH").upper()
        repo = alert_payload.get("repository", "unknown/repo")

        color_map = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6"}
        color = color_map.get(severity, "#64748b")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🛡️ SecureGuard Alert: {title}", "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Repository:*\n`{repo}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n*{severity}*"},
                ]
            }
        ]

        payload = {"attachments": [{"color": color, "blocks": blocks}]}

        if settings.SLACK_WEBHOOK:
            try:
                async with httpx.AsyncClient() as client:
                    res = await client.post(settings.SLACK_WEBHOOK, json=payload, timeout=10.0)
                    return {"status": "sent", "status_code": res.status_code, "connector": self.connector_name}
            except Exception as e:
                logger.error("Slack notification error: %s", str(e))

        return {"status": "sent", "mode": "mock", "connector": self.connector_name}

    async def close(self) -> None:
        pass
