"""
Purpose: GitHub Webhook signature validator and event router (Phase 2 stub).

Responsibilities:
- Verify HMAC SHA-256 signature of incoming webhooks.
- Parse payload into structured event models.
- Dispatch event to processing pipelines.

Dependencies:
- hmac
- hashlib

Usage:
    handler = WebhookHandler(secret="...")
    isValid = handler.verify_signature(payload, signature)
"""


from app.core.security import verify_webhook_signature


class WebhookHandler:
    """Validator and router for incoming GitHub webhook events."""

    def __init__(self, secret: str) -> None:
        self.secret = secret

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify GitHub HMAC SHA256 signature."""
        return verify_webhook_signature(payload, signature, self.secret)
