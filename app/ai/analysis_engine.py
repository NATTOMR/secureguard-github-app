"""
Purpose: AI Vulnerability Analysis Engine orchestrator for SecureGuard.

Responsibilities:
- Route finding to specialized prompt builder (Secrets, SAST, Dependency, Container, IaC).
- Compute risk scores, CVSS estimates, CWE, OWASP, and MITRE ATT&CK framework mappings.
- Format exact JSON response matching AIAnalysisResponse schema.
- Audit log AI analysis execution in database.

Dependencies:
- typing.Dict, Any, Optional
- app.ai.llm_client.LLMClient
- app.ai.prompt_builder.PromptBuilder
- app.ai.risk_score.RiskEngine
- app.ai.remediation_generator.RemediationGenerator
- app.ai.prompts.*
- app.schemas.ai_analysis.AIAnalysisResponse
- app.db.session.SessionLocal
- app.db.models.AIAnalysisModel

Usage:
    engine = AnalysisEngine()
    analysis = await engine.analyze_finding(title="...", severity="...", file_path="...", line=10, rule_id="...")
"""

import json
import time
from typing import Any, Dict, Optional

from app.ai.llm_client import LLMClient
from app.ai.prompt_builder import PromptBuilder
from app.ai.prompts.container_prompts import build_container_prompt
from app.ai.prompts.dependency_prompts import build_dependency_prompt
from app.ai.prompts.iac_prompts import build_iac_prompt
from app.ai.prompts.sast_prompts import build_sast_prompt
from app.ai.prompts.secrets_prompts import build_secrets_prompt
from app.ai.remediation_generator import RemediationGenerator
from app.ai.risk_score import RiskEngine
from app.core.logging import get_logger

logger = get_logger(__name__)


class AnalysisEngine:
    """Orchestrator for AI vulnerability analysis, prompt routing, and JSON formatting."""

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

    def _select_prompt(
        self,
        title: str,
        severity: str,
        file_path: str,
        line: Optional[int],
        rule_id: str,
        code_snippet: Optional[str],
        scanner: str = "Gitleaks",
    ) -> str:
        """Select category prompt template based on scanner and file extension."""
        scanner_lower = scanner.lower()
        file_lower = file_path.lower()

        if "secret" in scanner_lower or "gitleaks" in scanner_lower or "key" in rule_id or "token" in rule_id:
            return build_secrets_prompt(title, severity, file_path, line, rule_id, code_snippet)
        elif "docker" in file_lower or "container" in scanner_lower:
            return build_container_prompt(title, severity, file_path, line, rule_id, code_snippet)
        elif file_lower.endswith(".tf") or file_lower.endswith(".yaml") or "iac" in scanner_lower:
            return build_iac_prompt(title, severity, file_path, line, rule_id, code_snippet)
        elif "package" in file_lower or "requirements" in file_lower or "dependency" in scanner_lower:
            return build_dependency_prompt(title, severity, file_path, line, rule_id, code_snippet)
        else:
            return build_sast_prompt(title, severity, file_path, line, rule_id, code_snippet)

    async def analyze_finding(
        self,
        title: str,
        severity: str,
        file_path: str,
        line: Optional[int] = None,
        rule_id: str = "security-finding",
        code_snippet: Optional[str] = None,
        scanner: str = "Gitleaks",
    ) -> Dict[str, Any]:
        """Perform comprehensive AI security analysis for a finding."""
        start_time = time.time()

        # 1. Evaluate risk metrics & framework mappings
        risk = self.risk_engine.evaluate_risk(rule_id, severity)

        # 2. Select category prompt and invoke LLM
        prompt = self._select_prompt(title, severity, file_path, line, rule_id, code_snippet, scanner)
        llm_response = await self.llm_client.generate(prompt, self.prompt_builder.build_system_prompt())

        # 3. Generate remediation fix code
        remediation_data = await self.remediation_gen.generate_fix(
            code_snippet or "# Vulnerable code line", rule_id=rule_id
        )

        latency = time.time() - start_time

        # 4. Construct exact structured JSON response
        cwe_clean = risk["cwe"].split(":")[0].replace("CWE-", "")
        analysis_result = {
            "title": title,
            "summary": f"Security analysis for {severity} vulnerability in {file_path}:{line or 1}.",
            "technical_explanation": llm_response,
            "attack_scenario": (
                f"An attacker leverages {rule_id} vulnerability in {file_path} "
                f"to execute unauthorized actions, bypass access controls, or extract confidential data."
            ),
            "business_impact": (
                f"Financial penalties, operational disruption, compliance failure ({risk['owasp']}), "
                f"and brand reputation loss."
            ),
            "risk_level": severity.upper(),
            "confidence": "HIGH",
            "cvss_estimate": risk["cvss_estimate"],
            "cwe": risk["cwe"],
            "owasp": risk["owasp"],
            "mitre_attack": risk["mitre_attack"],
            "recommendation": remediation_data["explanation"],
            "secure_example": remediation_data["fixed_code"],
            "references": [
                f"https://cwe.mitre.org/data/definitions/{cwe_clean}.html",
                "https://owasp.org/www-project-top-ten/",
                "https://attack.mitre.org/",
            ],
        }

        # 5. Database audit logging
        try:
            from app.db.models import AIAnalysisModel
            from app.db.session import SessionLocal
            with SessionLocal() as db:
                record = AIAnalysisModel(
                    provider=self.llm_client.provider,
                    latency=round(latency, 3),
                    tokens_used=len(prompt.split()) + len(llm_response.split()),
                    analysis_json=json.dumps(analysis_result),
                )
                db.add(record)
                db.commit()
        except Exception as dbe:
            logger.warning("Could not persist AI analysis log to DB: %s", str(dbe))

        return analysis_result
