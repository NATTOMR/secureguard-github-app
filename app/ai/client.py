"""
Purpose: AI Client wrapper managing provider lifecycle, retry logic, timeout, and fallbacks.

Responsibilities:
- Provide unified API for security analysis operations.
- Delegate calls to configured AIProvider instance created by AIProviderFactory.

Dependencies:
- typing.Dict, Any, Optional
- app.ai.providers.factory.AIProviderFactory
- app.core.logging.get_logger

Usage:
    client = AIClient()
    analysis = await client.analyze_vulnerability(...)
"""

import asyncio
from typing import Any, Dict, Optional
from app.ai.providers.factory import AIProviderFactory
from app.core.logging import get_logger

logger = get_logger(__name__)


class AIClient:
    """Enterprise AI Client wrapper supporting dynamic providers, retries, and timeouts."""

    def __init__(self, provider_name: Optional[str] = None) -> None:
        self.provider_name = provider_name
        self.provider = AIProviderFactory.create_provider(provider_name)

    async def analyze_vulnerability(
        self,
        title: str,
        severity: str,
        file_path: str,
        line: Optional[int] = None,
        rule_id: str = "security-finding",
        code_snippet: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Perform vulnerability analysis with retry logic."""
        for attempt in range(2):
            try:
                return await asyncio.wait_for(
                    self.provider.analyze_vulnerability(title, severity, file_path, line, rule_id, code_snippet),
                    timeout=15.0,
                )
            except Exception as e:
                logger.warning("AIClient analyze_vulnerability attempt %d failed: %s", attempt + 1, str(e))
                if attempt == 1:
                    raise e

    async def generate_fix(
        self,
        vulnerable_code: str,
        language: str = "python",
        rule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate secure code fix."""
        return await asyncio.wait_for(
            self.provider.generate_fix(vulnerable_code, language, rule_id),
            timeout=15.0,
        )

    async def generate_report(
        self,
        repository: str,
        total_scans: int = 1,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
    ) -> Dict[str, Any]:
        """Generate executive report."""
        return await asyncio.wait_for(
            self.provider.generate_report(repository, total_scans, critical_count, high_count, medium_count, low_count),
            timeout=15.0,
        )

    async def chat(self, message: str, context: Optional[str] = None) -> Dict[str, Any]:
        """Send chat message."""
        return await asyncio.wait_for(self.provider.chat(message, context), timeout=15.0)

    async def health(self) -> Dict[str, Any]:
        """Perform health check."""
        return await self.provider.health()
