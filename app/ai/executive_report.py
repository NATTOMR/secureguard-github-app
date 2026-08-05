"""
Purpose: Executive Security Report generator module.

Responsibilities:
- Build executive security summaries, risk trend evaluations, compliance status reports, and top recommendation action plans.

Dependencies:
- typing.Dict, Any, List, Optional
- app.ai.llm_client.LLMClient
- app.models.scan_result.ScanResult

Usage:
    report_gen = ExecutiveReportGenerator()
    report = await report_gen.generate_report(repository="owner/repo", total_scans=10, critical_count=1, high_count=2, medium_count=3, low_count=1)
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.ai.llm_client import LLMClient


class ExecutiveReportGenerator:
    """Module for generating executive-level security reports."""

    def __init__(self, llm_client: Optional[LLMClient] = None) -> None:
        self.llm_client = llm_client or LLMClient()

    async def generate_report(
        self,
        repository: str,
        total_scans: int = 1,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
    ) -> Dict[str, Any]:
        """Generate structured Executive Security Report."""
        total_findings = critical_count + high_count + medium_count + low_count

        if critical_count > 0 or high_count > 0:
            security_posture = "NEEDS IMMEDIATE ATTENTION"
            compliance_status = "NON-COMPLIANT"
            risk_score = 8.5
        elif medium_count > 0:
            security_posture = "MODERATE RISK"
            compliance_status = "PARTIALLY COMPLIANT"
            risk_score = 5.2
        else:
            security_posture = "EXCELLENT / SECURE"
            compliance_status = "COMPLIANT"
            risk_score = 1.0

        prompt = (
            f"Generate Executive Summary for Repository: {repository}\n"
            f"Metrics: {critical_count} Critical, {high_count} High, {medium_count} Medium, {low_count} Low findings.\n"
            f"Security Posture: {security_posture}"
        )
        ai_summary = await self.llm_client.generate(prompt, "You are a Chief Information Security Officer (CISO).")

        return {
            "title": f"SecureGuard Executive Security Report — {repository}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "repository": repository,
            "security_posture": security_posture,
            "compliance_status": compliance_status,
            "overall_risk_score": risk_score,
            "summary_metrics": {
                "total_scans_evaluated": total_scans,
                "total_findings": total_findings,
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
            },
            "ciso_executive_summary": ai_summary,
            "top_recommendations": [
                "Remediate all CRITICAL and HIGH severity hardcoded secrets immediately.",
                "Enforce mandatory pre-commit Gitleaks hooks across developer workstations.",
                "Integrate SecureGuard GitHub Checks API into main branch protection rules.",
                "Conduct quarterly SAST rule audits and security awareness training.",
            ],
            "framework_compliance": {
                "OWASP_Top_10": "Pass with Warnings" if total_findings > 0 else "Pass",
                "NIST_CSF": "In Review",
                "ISO_27001": "Compliant",
            },
        }
