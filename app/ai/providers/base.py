"""
Purpose: Abstract Base Class for SecureGuard AI Providers.

Responsibilities:
- Define uniform interface contracts for all LLM providers (OpenAI, Gemini, Claude, Ollama, Azure).

Dependencies:
- abc.ABC, abstractmethod
- typing.Dict, Any, Optional

Usage:
    class MyProvider(AIProvider):
        ...
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class AIProvider(ABC):
    """Abstract Base Class for provider-agnostic LLM integration."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return canonical string identifier of provider."""
        pass

    @abstractmethod
    async def analyze_vulnerability(
        self,
        title: str,
        severity: str,
        file_path: str,
        line: Optional[int] = None,
        rule_id: str = "security-finding",
        code_snippet: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Perform vulnerability analysis and generate risk mappings."""
        pass

    @abstractmethod
    async def generate_fix(
        self,
        vulnerable_code: str,
        language: str = "python",
        rule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate secure code fix and explanation."""
        pass

    @abstractmethod
    async def generate_report(
        self,
        repository: str,
        total_scans: int = 1,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
    ) -> Dict[str, Any]:
        """Generate executive CISO security summary report."""
        pass

    @abstractmethod
    async def chat(self, message: str, context: Optional[str] = None) -> Dict[str, Any]:
        """Interactive security chat assistant conversation."""
        pass

    @abstractmethod
    async def health(self) -> Dict[str, Any]:
        """Perform health check on provider API connectivity."""
        pass
