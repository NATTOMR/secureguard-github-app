"""
Purpose: Automated tests for root and health endpoints.

Responsibilities:
- Test GET / returns status 200 and expected payload structure.
- Test GET /health returns status 200 and health check info.
- Test POST /webhook stub endpoint returns status 200.

Dependencies:
- pytest
- app.schemas.health.HealthResponse, RootResponse

Usage:
    pytest tests/test_health.py
"""

from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient) -> None:
    """Test that GET / returns status 200 and expected app metadata."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "SecureGuard"
    assert data["status"] == "operational"
    assert "version" in data
    assert data["docs_url"] == "/docs"


def test_health_endpoint(client: TestClient) -> None:
    """Test that GET /health returns status 200 and healthy checks."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "SecureGuard"
    assert "checks" in data
    assert data["checks"]["app"] == "ok"


def test_webhook_stub_endpoint(client: TestClient) -> None:
    """Test that POST /webhook returns status 200 and acknowledgment."""
    headers = {
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": "test-delivery-12345",
    }
    response = client.post("/webhook", json={"ref": "refs/heads/main"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "received"
    assert data["event"] == "push"
    assert data["delivery_id"] == "test-delivery-12345"
