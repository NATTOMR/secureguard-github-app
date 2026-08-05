"""
Purpose: Specialized AI Prompt Builder for Secrets Scanner Findings (Gitleaks).

Responsibilities:
- Build tailored prompts for secret leaks, API key exposure, and credential rotation guidance.

Dependencies:
- typing.Dict, Any, Optional

Usage:
    from app.ai.prompts.secrets_prompts import build_secrets_prompt
"""

from typing import Optional


def build_secrets_prompt(
    title: str,
    severity: str,
    file_path: str,
    line: Optional[int],
    rule_id: str,
    code_snippet: Optional[str] = None,
) -> str:
    """Build prompt tailored for secret & credential leaks."""
    return (
        f"Category: SECRETS_LEAK\n"
        f"Finding: {title}\n"
        f"Severity: {severity}\n"
        f"File: {file_path}:{line or 1}\n"
        f"Rule ID: {rule_id}\n"
        f"Exposed Secret Snippet: {code_snippet or '[Redacted Secret]'}\n\n"
        "Analyze this secret leak and produce a JSON response with fields:\n"
        "title, summary, technical_explanation, attack_scenario, business_impact, "
        "risk_level, confidence, cvss_estimate, cwe, owasp, mitre_attack, "
        "recommendation, secure_example, references."
    )
