"""
Purpose: Automated tests for Gitleaks scanner and secret rules.

Responsibilities:
- Verify that secret rules correctly identify various types of secrets.
- Verify that GitleaksScanner traverses directories and finds secrets.

Dependencies:
- pytest
- app.scanners.secret_rules.detect_secrets
- app.scanners.gitleaks.GitleaksScanner

Usage:
    pytest tests/test_gitleaks.py -v
"""

import pytest
from app.scanners.secret_rules import detect_secrets
from app.scanners.gitleaks import GitleaksScanner
import tempfile
from pathlib import Path

def test_detect_secrets_github_token():
    """Test detection of GitHub Personal Access Tokens."""
    content = "my_token = '" + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'"
    findings = detect_secrets(content, "test.py")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "github-pat"
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["line_number"] == 1

def test_detect_secrets_aws_key():
    """Test detection of AWS Access Key ID."""
    content = "aws_access_key_id=" + "AKIA" + "IOSFODNN7EXAMPLE"
    findings = detect_secrets(content, "config.ini")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "aws-access-key"
    assert findings[0]["severity"] == "HIGH"

def test_detect_secrets_env_file():
    """Test detection of .env files."""
    content = "DEBUG=True"
    findings = detect_secrets(content, ".env")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "exposed-env-file"

@pytest.mark.asyncio
async def test_gitleaks_scanner():
    """Test GitleaksScanner directory traversal and detection."""
    scanner = GitleaksScanner()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a file with a secret
        secret_file = temp_path / "app.py"
        dummy_key = "sk_test_" + "1234567890abcdef12345678"
        secret_file.write_text(f"api_key = '{dummy_key}'")
        
        # Create a normal file
        normal_file = temp_path / "readme.md"
        normal_file.write_text("Hello World")
        
        findings = await scanner.scan(temp_path)
        
        assert len(findings) == 2
        rule_ids = [f["rule_id"] for f in findings]
        assert "stripe-key" in rule_ids
        assert "generic-api-key" in rule_ids
        assert findings[0]["file_path"] == "app.py"
