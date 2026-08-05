"""
Purpose: AI Provider Factory for dynamic LLM provider instantiation.

Responsibilities:
- Register available AI providers.
- Instantiate configured provider class based on settings or explicit name.

Dependencies:
- typing.Dict, Type, List
- app.ai.providers.base.AIProvider
- app.ai.providers.openai_provider.OpenAIProvider
- app.ai.providers.gemini_provider.GeminiProvider
- app.ai.providers.claude_provider.ClaudeProvider
- app.ai.providers.ollama_provider.OllamaProvider
- app.ai.providers.azure_provider.AzureOpenAIProvider
- app.core.config.get_settings

Usage:
    provider = AIProviderFactory.create_provider()
"""

from typing import Dict, List, Type
from app.ai.providers.azure_provider import AzureOpenAIProvider
from app.ai.providers.base import AIProvider
from app.ai.providers.claude_provider import ClaudeProvider
from app.ai.providers.gemini_provider import GeminiProvider
from app.ai.providers.ollama_provider import OllamaProvider
from app.ai.providers.openai_provider import OpenAIProvider
from app.core.config import get_settings


class AIProviderFactory:
    """Factory for instantiating AIProvider implementations."""

    _registry: Dict[str, Type[AIProvider]] = {
        "openai": OpenAIProvider,
        "gemini": GeminiProvider,
        "claude": ClaudeProvider,
        "ollama": OllamaProvider,
        "azure": AzureOpenAIProvider,
    }

    @classmethod
    def register_provider(cls, name: str, provider_cls: Type[AIProvider]) -> None:
        """Register a new provider implementation dynamically."""
        cls._registry[name.lower()] = provider_cls

    @classmethod
    def list_providers(cls) -> List[str]:
        """List registered provider identifiers."""
        return list(cls._registry.keys())

    @classmethod
    def create_provider(cls, provider_name: str = None) -> AIProvider:
        """Instantiate configured or requested AIProvider."""
        settings = get_settings()
        target_name = (provider_name or settings.AI_PROVIDER).lower()

        provider_cls = cls._registry.get(target_name)
        if not provider_cls:
            # Fallback to OpenAIProvider if unknown provider is requested
            provider_cls = OpenAIProvider

        return provider_cls()
