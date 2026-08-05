"""
Purpose: OpenAI LLM Provider implementation.

Responsibilities:
- Implement AIProvider for OpenAI GPT models.

Dependencies:
- app.ai.providers.base.AIProvider
- app.ai.analysis_engine.AnalysisEngine
- app.ai.remediation_generator.RemediationGenerator
- app.ai.executive_report.ExecutiveReportGenerator
- app.core.config.get_settings

Usage:
    provider = OpenAIProvider()
"""

from typing import Any, Dict, Optional
from app.ai.analysis_engine import AnalysisEngine
from app.ai.executive_report import ExecutiveReportGenerator
from app.ai.providers.base import AIProvider
from app.ai.remediation_generator import RemediationGenerator
from app.core.config import get_settings


class OpenAIProvider(AIProvider):
    """OpenAI LLM Provider."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.engine = AnalysisEngine()
        self.remediation = RemediationGenerator()
        self.report_gen = ExecutiveReportGenerator()

    @property
    def provider_name(self) -> str:
        return "openai"

    async def analyze_vulnerability(
        self,
        title: str,
        severity: str,
        file_path: str,
        line: Optional[int] = None,
        rule_id: str = "security-finding",
        code_snippet: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await self.engine.analyze_finding(title, severity, file_path, line, rule_id, code_snippet)

    async def generate_fix(
        self,
        vulnerable_code: str,
        language: str = "python",
        rule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await self.remediation.generate_fix(vulnerable_code, language, rule_id)

    async def generate_report(
        self,
        repository: str,
        total_scans: int = 1,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
    ) -> Dict[str, Any]:
        return await self.report_gen.generate_report(repository, total_scans, critical_count, high_count, medium_count, low_count)

    async def chat(self, message: str, context: Optional[str] = None) -> Dict[str, Any]:
        reply = await self.engine.llm_client.generate(message, context)
        return {"user_message": message, "assistant_reply": reply, "provider": self.provider_name}

    async def health(self) -> Dict[str, Any]:
        has_key = bool(self.settings.OPENAI_API_KEY)
        return {
            "provider": self.provider_name,
            "status": "healthy" if has_key else "degraded",
            "configured": has_key,
            "model": self.settings.OPENAI_MODEL,
        }
