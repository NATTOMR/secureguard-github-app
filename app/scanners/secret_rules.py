"""
Purpose: Define regex patterns and logic for secret detection.

Responsibilities:
- Provide high-performance regex rules to identify secrets like AWS keys, GitHub tokens, JWTs, etc.
- Provide a fallback detection engine in Python for environments without the Gitleaks binary.

Dependencies:
- re

Usage:
    from app.scanners.secret_rules import detect_secrets
    findings = detect_secrets("file_content", "path/to/file.py")
"""

import re
from typing import List, Dict, Any

# Define a set of robust regular expressions for secret scanning.
SECRET_RULES = [
    {
        "id": "github-pat",
        "description": "GitHub Personal Access Token",
        "regex": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"),
        "severity": "CRITICAL",
    },
    {
        "id": "aws-access-key",
        "description": "AWS Access Key ID",
        "regex": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "severity": "HIGH",
    },
    {
        "id": "aws-secret-key",
        "description": "AWS Secret Access Key",
        "regex": re.compile(r"(?i)aws_?secret_?(?:access_?)?key\s*(=|:)\s*['\"]?[a-zA-Z0-9/+=]{40}['\"]?"),
        "severity": "CRITICAL",
    },
    {
        "id": "jwt-token",
        "description": "JSON Web Token",
        "regex": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "severity": "HIGH",
    },
    {
        "id": "generic-api-key",
        "description": "Generic API Key",
        "regex": re.compile(r"(?i)(?:api_?key|api_?token|auth_?token|access_?token)\s*(=|:)\s*['\"][a-zA-Z0-9\-_]{16,}['\"]"),
        "severity": "MEDIUM",
    },
    {
        "id": "slack-token",
        "description": "Slack Token",
        "regex": re.compile(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}"),
        "severity": "HIGH",
    },
    {
        "id": "stripe-key",
        "description": "Stripe API Key",
        "regex": re.compile(r"(?:sk|rk)_(?:test|live)_[a-zA-Z0-9]{24}"),
        "severity": "HIGH",
    },
]


def detect_secrets(content: str, file_path: str) -> List[Dict[str, Any]]:
    """Scan file content using defined rules and return a list of findings."""
    findings = []
    
    # Simple check for exposed .env files
    if file_path.endswith(".env") or ".env." in file_path:
        findings.append({
            "rule_id": "exposed-env-file",
            "title": "Exposed Environment File",
            "severity": "HIGH",
            "file_path": file_path,
            "line_number": 1,
            "description": "A .env file was detected in the repository.",
            "recommendation": "Remove .env files from version control and use environment variables.",
            "scanner_name": "SecureGuard-Native",
        })

    lines = content.splitlines()
    for i, line in enumerate(lines):
        line_number = i + 1
        for rule in SECRET_RULES:
            for match in rule["regex"].finditer(line):
                findings.append({
                    "rule_id": rule["id"],
                    "title": rule["description"],
                    "severity": rule["severity"],
                    "file_path": file_path,
                    "line_number": line_number,
                    "description": f"Found potential {rule['description']}",
                    "recommendation": f"Revoke the leaked {rule['description']} and rotate the credential.",
                    "scanner_name": "SecureGuard-Native",
                })
    return findings
