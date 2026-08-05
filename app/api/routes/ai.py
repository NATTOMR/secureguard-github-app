"""
Purpose: REST API router for AI Security Assistant features.

Responsibilities:
- Provide /api/ai/analyze for AI vulnerability analysis.
- Provide /api/ai/fix for secure code generation.
- Provide /api/ai/report for executive security reports.
- Provide /api/ai/chat for interactive security chat assistant.

Dependencies:
- fastapi.APIRouter, status
- app.ai.analysis_engine.AnalysisEngine
- app.ai.remediation_generator.RemediationGenerator
- app.ai.executive_report.ExecutiveReportGenerator
- app.ai.llm_client.LLMClient
- app.ai.prompt_builder.PromptBuilder
- app.schemas.ai.*

Usage:
    Included in main API router.
"""

from typing import Any, Dict
from fastapi import APIRouter, status

from app.ai.analysis_engine import AnalysisEngine
from app.ai.executive_report import ExecutiveReportGenerator
from app.ai.llm_client import LLMClient
from app.ai.prompt_builder import PromptBuilder
from app.ai.remediation_generator import RemediationGenerator
from app.schemas.ai import AnalyzeRequest, ChatRequest, FixRequest, ReportRequest

router = APIRouter(prefix="/api/ai", tags=["AI Security Assistant"])


@router.post(
    "/analyze",
    status_code=status.HTTP_200_OK,
    summary="AI Vulnerability Analysis",
    description="Generates AI vulnerability explanation, attack scenario, CVSS/CWE/OWASP mappings, and recommendations.",
)
async def analyze_vulnerability(req: AnalyzeRequest) -> Dict[str, Any]:
    """Perform AI vulnerability analysis."""
    engine = AnalysisEngine()
    result = await engine.analyze_finding(
        title=req.title,
        severity=req.severity,
        file_path=req.file,
        line=req.line,
        rule_id=req.rule_id,
        code_snippet=req.code_snippet,
    )
    return result


@router.post(
    "/fix",
    status_code=status.HTTP_200_OK,
    summary="AI Secure Code Fix Generator",
    description="Generates side-by-side secure code refactoring for vulnerable snippets.",
)
async def generate_secure_fix(req: FixRequest) -> Dict[str, Any]:
    """Generate secure code fix."""
    generator = RemediationGenerator()
    result = await generator.generate_fix(
        vulnerable_code=req.vulnerable_code,
        language=req.language,
        rule_id=req.rule_id,
    )
    return result


@router.post(
    "/report",
    status_code=status.HTTP_200_OK,
    summary="AI Executive Security Report",
    description="Builds executive summary, CISO evaluation, risk posture, and compliance report.",
)
async def generate_executive_report(req: ReportRequest) -> Dict[str, Any]:
    """Generate CISO executive security report."""
    generator = ExecutiveReportGenerator()
    result = await generator.generate_report(
        repository=req.repository,
        total_scans=req.total_scans,
        critical_count=req.critical_count,
        high_count=req.high_count,
        medium_count=req.medium_count,
        low_count=req.low_count,
    )
    return result


@router.post(
    "/chat",
    status_code=status.HTTP_200_OK,
    summary="AI Security Chat Assistant",
    description="Interactive chat assistant answering security questions and CWE/CVE explanations.",
)
async def chat_assistant(req: ChatRequest) -> Dict[str, Any]:
    """Interactive AI chat assistant."""
    llm = LLMClient()
    pb = PromptBuilder()
    prompt = pb.build_chat_prompt(req.message, req.context)
    reply = await llm.generate(prompt, pb.build_system_prompt())

    return {
        "user_message": req.message,
        "assistant_reply": reply,
    }
