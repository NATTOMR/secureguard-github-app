"""
Purpose: AI Analysis Engine orchestrator for SecureGuard.

Responsibilities:
- Combine LLMClient, PromptBuilder, RiskEngine, and RemediationGenerator into unified vulnerability analysis pipeline.

Dependencies:
- typing.Dict, Any, Optional
- app.ai.llm_client.LLMClient
- app.ai.prompt_builder.PromptBuilder
- app.ai.risk_score.RiskEngine
- app.ai.remediation_generator.RemediationGenerator

Usage:
    engine = AnalysisEngine()
    analysis = await engine.analyze_finding(title="...", severity="...", file_path="...", line=10, rule_id="...")
"""

from typing import Any, Dict, Optional

from app.ai.llm_client import LLMClient
from app.ai.prompt_builder import PromptBuilder
from app.ai.remediation_generator import RemediationGenerator
from app.ai.risk_score import RiskEngine


class AnalysisEngine:
    """Orchestrator for AI vulnerability analysis and risk evaluation."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        risk_engine: Optional[RiskEngine] = None,
        remediation_gen: Optional[RemediationGenerator] = None,
    ) -> None:
        self.llm_client = llm_client or LLMClient()
        self.risk_engine = risk_engine or RiskEngine()
        self.remediation_gen = remediation_gen or RemediationGenerator()
        self.prompt_builder = PromptBuilder()

    async def analyze_finding(
        self,
        title: str,
        severity: str,
        file_path: str,
        line: Optional[int] = None,
        rule_id: str = "security-finding",
        code_snippet: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Perform comprehensive AI security analysis for a finding."""
        # 1. Compute risk score & compliance mappings
        risk_card = self.risk_engine.evaluate_risk(rule_id, severity)

        # 2. Build prompt and invoke LLM
        prompt = self.prompt_builder.build_vulnerability_prompt(
            title, severity, file_path, line, rule_id, code_snippet
        )
        ai_explanation = await self.llm_client.generate(prompt, self.prompt_builder.build_system_prompt())

        # 3. Generate remediation fix if snippet provided
        remediation = None
        if code_snippet:
            remediation = await self.remediation_gen.generate_fix(code_snippet, rule_id=rule_id)

        return {
            "finding": {
                "title": title,
                "severity": severity,
                "file": file_path,
                "line": line,
                "rule_id": rule_id,
            },
            "risk_analysis": risk_card,
            "ai_explanation": ai_explanation,
            "remediation": remediation,
            "references": [
                f"https://cwe.mitre.org/data/definitions/{risk_card['cwe'].split(':')[0].replace('CWE-', '')}.html",
                "https://owasp.org/www-project-top-ten/",
            ],
        }
