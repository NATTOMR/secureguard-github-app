"""
Purpose: Test suite for AI Security Assistant, LLM Client, Risk Engine, and REST APIs.

Responsibilities:
- Test PromptBuilder template generation.
- Test LLMClient heuristic fallback and caching.
- Test RiskEngine scoring and CWE/OWASP/MITRE mapping.
- Test RemediationGenerator secure code fix generation.
- Test ExecutiveReportGenerator report formatting.
- Test /api/ai/analyze, /api/ai/fix, /api/ai/report, and /api/ai/chat REST endpoints.

Dependencies:
- pytest
- unittest.mock
- app.ai.llm_client.LLMClient
- app.ai.prompt_builder.PromptBuilder
- app.ai.risk_score.RiskEngine
- app.ai.remediation_generator.RemediationGenerator
- app.ai.executive_report.ExecutiveReportGenerator

Usage:
    pytest tests/test_ai_assistant.py -v
"""

from unittest.mock import AsyncMock, patch
import pytest

from app.ai.executive_report import ExecutiveReportGenerator
from app.ai.llm_client import LLMClient
from app.ai.prompt_builder import PromptBuilder
from app.ai.remediation_generator import RemediationGenerator
from app.ai.risk_score import RiskEngine


@pytest.mark.asyncio
async def test_llm_client_fallback():
    """Test LLMClient heuristic fallback when live API keys are omitted."""
    client = LLMClient(provider="openai")
    res = await client.generate("Analyze hardcoded token", system_prompt="Security AI")
    assert "Hardcoded Secret" in res
    assert "Remediation" in res


def test_prompt_builder():
    """Test PromptBuilder template output."""
    pb = PromptBuilder()
    prompt = pb.build_vulnerability_prompt("Eval Injection", "HIGH", "app.py", 10, "python-eval")
    assert "Eval Injection" in prompt
    assert "app.py" in prompt
    assert "python-eval" in prompt


def test_risk_engine_scoring():
    """Test RiskEngine scoring and compliance framework mapping."""
    engine = RiskEngine()
    score = engine.evaluate_risk("aws-access-key", "CRITICAL")
    assert score["cvss_estimate"] == 9.8
    assert "CWE-798" in score["cwe"]
    assert "A07:2021" in score["owasp"]
    assert "T1552.001" in score["mitre_attack"]


@pytest.mark.asyncio
async def test_remediation_generator():
    """Test RemediationGenerator secure code fix generation."""
    generator = RemediationGenerator()
    res = await generator.generate_fix("eval(user_input)", language="python", rule_id="python-eval")
    assert "ast.literal_eval" in res["fixed_code"]
    assert "ast.literal_eval" in res["explanation"]


@pytest.mark.asyncio
async def test_executive_report_generator():
    """Test ExecutiveReportGenerator executive summary report."""
    generator = ExecutiveReportGenerator()
    report = await generator.generate_report("octocat/Hello-World", total_scans=5, critical_count=1)
    assert report["security_posture"] == "NEEDS IMMEDIATE ATTENTION"
    assert report["compliance_status"] == "NON-COMPLIANT"
    assert "summary_metrics" in report


def test_api_ai_analyze_endpoint(client):
    """Test POST /api/ai/analyze endpoint."""
    payload = {
        "title": "Hardcoded AWS Key",
        "severity": "CRITICAL",
        "file": "aws.py",
        "line": 12,
        "rule_id": "aws-access-key",
        "code_snippet": "AWS_SECRET = 'sk_test_12345'",
    }
    res = client.post("/api/ai/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "cvss_estimate" in data
    assert "cwe" in data


def test_api_ai_fix_endpoint(client):
    """Test POST /api/ai/fix endpoint."""
    payload = {
        "vulnerable_code": "eval(user_input)",
        "language": "python",
        "rule_id": "python-eval",
    }
    res = client.post("/api/ai/fix", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "fixed_code" in data
    assert "explanation" in data


def test_api_ai_report_endpoint(client):
    """Test POST /api/ai/report endpoint."""
    payload = {
        "repository": "octocat/Hello-World",
        "total_scans": 3,
        "critical_count": 0,
        "high_count": 1,
    }
    res = client.post("/api/ai/report", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "ciso_executive_summary" in data


def test_api_ai_chat_endpoint(client):
    """Test POST /api/ai/chat endpoint."""
    payload = {
        "message": "What is CWE-798 and how to prevent it?",
    }
    res = client.post("/api/ai/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "assistant_reply" in data
