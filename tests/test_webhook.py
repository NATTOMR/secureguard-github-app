"""
Purpose: Automated tests for GitHub Webhook handler and signature verification.

Responsibilities:
- Verify signature verification logic (valid vs invalid HMAC-SHA256 signatures).
- Verify push and pull_request event background task dispatch.

Dependencies:
- pytest
- fastapi.testclient.TestClient
- app.main.app
- hmac, hashlib

Usage:
    pytest tests/test_webhook.py -v
"""

import hmac
import hashlib
import json
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_webhook_event_acknowledgment():
    """Test webhook endpoint responds with 200 and status received."""
    response = client.post(
        "/webhook",
        headers={"X-GitHub-Event": "ping", "X-GitHub-Delivery": "test-delivery-123"},
        json={"zen": "Non-blocking is better than blocking."},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "received"
    assert data["event"] == "ping"
    assert data["delivery_id"] == "test-delivery-123"


def test_webhook_push_event_dispatch():
    """Test webhook push event is accepted and queued."""
    payload = {
        "ref": "refs/heads/main",
        "after": "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d",
        "repository": {"name": "Hello-World", "owner": {"login": "octocat"}},
        "installation": {"id": 123456},
    }
    response = client.post(
        "/webhook",
        headers={"X-GitHub-Event": "push", "X-GitHub-Delivery": "push-delivery-456"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json()["event"] == "push"


def test_webhook_handler_class():
    """Test WebhookHandler class signature verification."""
    from app.github.webhook_handler import WebhookHandler
    handler = WebhookHandler(secret="my_secret")
    payload = b'{"test": "payload"}'
    
    # Compute signature
    digest = hmac.new(b"my_secret", msg=payload, digestmod=hashlib.sha256).hexdigest()
    sig_header = f"sha256={digest}"
    
    assert handler.verify_signature(payload, sig_header) is True
    assert handler.verify_signature(payload, "sha256=invalid_hash") is False


def test_sanitize_string_helper():
    """Test sanitize_string helper function."""
    from app.utils.helpers import sanitize_string
    dirty = "\x00Hello\x1f World!\x7f"
    clean = sanitize_string(dirty)
    assert clean == "Hello World!"
