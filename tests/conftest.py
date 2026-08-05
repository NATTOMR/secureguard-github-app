"""
Purpose: Pytest configuration and shared fixtures for API testing.

Responsibilities:
- Provide `TestClient` and `AsyncClient` fixtures for FastAPI app.

Dependencies:
- pytest
- httpx.AsyncClient, httpx.ASGITransport
- app.main.create_app

Usage:
    def test_example(client):
        response = client.get("/")
"""

from typing import AsyncGenerator, Generator
import os
import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from app.main import create_app


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """Ensure GITHUB_APP_ID is set during test runs if missing from environment."""
    from app.core.config import get_settings
    monkeypatch.setenv("GITHUB_APP_ID", "4492546")
    get_settings.cache_clear()


@pytest.fixture
def app():
    """Create and configure a fresh FastAPI app instance for testing."""
    return create_app()


@pytest.fixture
def client(app) -> Generator[TestClient, None, None]:
    """Synchronous FastAPI TestClient fixture."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
async def async_client(app) -> AsyncGenerator[AsyncClient, None]:
    """Asynchronous httpx AsyncClient fixture."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
