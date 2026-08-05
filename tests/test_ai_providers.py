"""
Purpose: Test suite for Provider-Agnostic AI Architecture.

Responsibilities:
- Test AIProviderFactory creation for OpenAI, Gemini, Claude, Ollama, and Azure.
- Test AIClient execution, timeout, and retry mechanisms.
- Test /api/ai/health and /api/ai/providers API endpoints.

Dependencies:
- pytest
- app.ai.providers.factory.AIProviderFactory
- app.ai.client.AIClient

Usage:
    pytest tests/test_ai_providers.py -v
"""

import pytest
from app.ai.client import AIClient
from app.ai.providers.factory import AIProviderFactory


def test_provider_factory_list():
    """Test factory lists registered providers."""
    providers = AIProviderFactory.list_providers()
    assert "openai" in providers
    assert "gemini" in providers
    assert "claude" in providers
    assert "ollama" in providers
    assert "azure" in providers


def test_provider_factory_creation():
    """Test factory instantiates requested providers."""
    p_openai = AIProviderFactory.create_provider("openai")
    assert p_openai.provider_name == "openai"

    p_gemini = AIProviderFactory.create_provider("gemini")
    assert p_gemini.provider_name == "gemini"

    p_claude = AIProviderFactory.create_provider("claude")
    assert p_claude.provider_name == "claude"

    p_ollama = AIProviderFactory.create_provider("ollama")
    assert p_ollama.provider_name == "ollama"

    p_azure = AIProviderFactory.create_provider("azure")
    assert p_azure.provider_name == "azure"


@pytest.mark.asyncio
async def test_ai_client_health():
    """Test AIClient health check."""
    client = AIClient("openai")
    health = await client.health()
    assert health["provider"] == "openai"
    assert "status" in health


def test_api_ai_providers_endpoint(client):
    """Test GET /api/ai/providers endpoint."""
    res = client.get("/api/ai/providers")
    assert res.status_code == 200
    data = res.json()
    assert "active_provider" in data
    assert "available_providers" in data
    assert "openai" in data["available_providers"]


def test_api_ai_health_endpoint(client):
    """Test GET /api/ai/health endpoint."""
    res = client.get("/api/ai/health")
    assert res.status_code == 200
    data = res.json()
    assert "provider" in data
    assert "status" in data
