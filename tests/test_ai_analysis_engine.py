"""
Purpose: Test suite for AI Vulnerability Analysis Engine, specialized prompt builders, and JSON response schema.

Responsibilities:
- Test Secrets, SAST, Dependency, Container, and IaC prompt builders.
- Test AnalysisEngine category prompt routing logic.
- Test exact JSON output schema structure (AIAnalysisResponse).
- Test database audit logging for AI analysis records.

Dependencies:
- pytest
- app.ai.analysis_engine.AnalysisEngine
- app.ai.prompts.*

Usage:
    pytest tests/test_ai_analysis_engine.py -v
"""

import pytest
from app.ai.analysis_engine import AnalysisEngine
from app.ai.prompts import (
    build_container_prompt,
    build_dependency_prompt,
    build_iac_prompt,
    build_sast_prompt,
    build_secrets_prompt,
)


def test_specialized_prompts():
    """Test category prompt builders."""
    sec_p = build_secrets_prompt("Secret Leak", "CRITICAL", "aws.py", 10, "aws-key")
    assert "SECRETS_LEAK" in sec_p

    sast_p = build_sast_prompt("Eval Injection", "HIGH", "app.py", 5, "python-eval")
    assert "SAST_VULNERABILITY" in sast_p

    dep_p = build_dependency_prompt("Vulnerable Package", "HIGH", "requirements.txt", 1, "CVE-2024-1234")
    assert "DEPENDENCY_VULNERABILITY" in dep_p

    cnt_p = build_container_prompt("Root Docker User", "MEDIUM", "Dockerfile", 2, "docker-root")
    assert "CONTAINER_SECURITY" in cnt_p

    iac_p = build_iac_prompt("S3 Public Read", "HIGH", "main.tf", 12, "aws-s3-public")
    assert "IAC_MISCONFIGURATION" in iac_p


@pytest.mark.asyncio
async def test_analysis_engine_routing_and_schema():
    """Test AnalysisEngine analysis generation and schema compliance."""
    engine = AnalysisEngine()
    analysis = await engine.analyze_finding(
        title="Hardcoded AWS Secret Key",
        severity="CRITICAL",
        file_path="config/aws.py",
        line=14,
        rule_id="aws-access-key",
        code_snippet="AWS_SECRET = 'sk_test_12345'",
        scanner="Gitleaks",
    )

    assert analysis["title"] == "Hardcoded AWS Secret Key"
    assert analysis["risk_level"] == "CRITICAL"
    assert "cvss_estimate" in analysis
    assert "cwe" in analysis
    assert "owasp" in analysis
    assert "mitre_attack" in analysis
    assert "attack_scenario" in analysis
    assert "business_impact" in analysis
    assert "recommendation" in analysis
    assert "secure_example" in analysis
    assert isinstance(analysis["references"], list)


def test_api_ai_analyze_structured_response(client):
    """Test POST /api/ai/analyze returns compliant AIAnalysisResponse JSON."""
    payload = {
        "title": "Unsafe eval usage",
        "severity": "HIGH",
        "file": "app/main.py",
        "line": 42,
        "rule_id": "python-eval",
        "code_snippet": "eval(user_input)",
    }
    res = client.post("/api/ai/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["title"] == "Unsafe eval usage"
    assert data["risk_level"] == "HIGH"
    assert "technical_explanation" in data
    assert "attack_scenario" in data
    assert "business_impact" in data
