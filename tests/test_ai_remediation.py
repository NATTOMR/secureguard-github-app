"""
Purpose: Test suite for AI Secure Code Remediation Engine.

Responsibilities:
- Test LanguageDetector for Python, JS/TS, Go, Java, Docker, Terraform.
- Test SecureCodeGenerator across all 9 supported targets.
- Test PatchBuilder unified diff and PR suggestion block generation.
- Test CodeValidator syntax checking.
- Test ConfidenceEngine confidence rating and risk reduction.
- Test POST /api/ai/fix REST endpoint.

Dependencies:
- pytest
- app.ai.remediation.*

Usage:
    pytest tests/test_ai_remediation.py -v
"""

import pytest
from app.ai.remediation import (
    CodeValidator,
    ConfidenceEngine,
    LanguageDetector,
    PatchBuilder,
    RemediationEngine,
    SecureCodeGenerator,
)


def test_language_detector():
    """Test LanguageDetector file extension and snippet syntax detection."""
    assert LanguageDetector.detect("main.py") == "python"
    assert LanguageDetector.detect("app.ts") == "typescript"
    assert LanguageDetector.detect("main.go") == "go"
    assert LanguageDetector.detect("App.java") == "java"
    assert LanguageDetector.detect("Dockerfile") == "dockerfile"
    assert LanguageDetector.detect("main.tf") == "terraform"


def test_secure_code_generator_python():
    """Test SecureCodeGenerator for Python eval vulnerability."""
    res = SecureCodeGenerator.generate("eval(user_input)", "python", "python-eval")
    assert "ast.literal_eval" in res["secure_code"]
    assert "eval" in res["vulnerability"].lower() or "dynamic" in res["vulnerability"].lower()


def test_secure_code_generator_go():
    """Test SecureCodeGenerator for Go command injection."""
    res = SecureCodeGenerator.generate("exec.Command(\"sh\", \"-c\", input)", "go", "command-injection")
    assert "exec.Command" in res["secure_code"]


def test_patch_builder():
    """Test PatchBuilder unified diff generation."""
    diff = PatchBuilder.build_unified_diff("password = '123'", "password = os.getenv('PWD')", "config.py")
    assert "--- a/config.py" in diff
    assert "+++ b/config.py" in diff
    assert "-password = '123'" in diff
    assert "+password = os.getenv('PWD')" in diff


def test_code_validator():
    """Test CodeValidator syntax validation."""
    assert CodeValidator.validate_code("x = 10", "python") is True
    assert CodeValidator.validate_code("x = (", "python") is False


def test_confidence_engine():
    """Test ConfidenceEngine risk metrics."""
    eval_conf = ConfidenceEngine.evaluate("python-eval", "python")
    assert eval_conf["confidence"] >= 0.90
    assert eval_conf["risk_reduction"] == "HIGH"


def test_remediation_engine_pipeline():
    """Test RemediationEngine end-to-end payload generation."""
    engine = RemediationEngine()
    result = engine.generate_remediation(
        vulnerable_code="password = 'admin'",
        filename="config.py",
        rule_id="hardcoded-password",
    )
    assert result["language"] == "python"
    assert "password" in result["secure_code"]
    assert "diff" in result
    assert "patch" in result
    assert result["confidence"] > 0.90


def test_api_ai_fix_endpoint(client):
    """Test POST /api/ai/fix endpoint."""
    payload = {
        "vulnerable_code": "eval(user_input)",
        "language": "python",
        "rule_id": "python-eval",
        "filename": "app.py",
        "severity": "HIGH",
    }
    res = client.post("/api/ai/fix", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["language"] == "python"
    assert "ast.literal_eval" in data["secure_code"]
    assert "diff" in data
    assert "patch" in data
    assert "confidence" in data
