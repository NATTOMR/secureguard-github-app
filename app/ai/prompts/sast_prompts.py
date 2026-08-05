"""
Purpose: Specialized AI Prompt Builder for SAST Findings (Semgrep).

Responsibilities:
- Build tailored prompts for code injection, XSS, unsafe deserialization, and cryptography flaws.

Dependencies:
- typing.Optional
"""

from typing import Optional


def build_sast_prompt(
    title: str,
    severity: str,
    file_path: str,
    line: Optional[int],
    rule_id: str,
    code_snippet: Optional[str] = None,
) -> str:
    """Build prompt tailored for SAST vulnerabilities."""
    return (
        f"Category: SAST_VULNERABILITY\n"
        f"Finding: {title}\n"
        f"Severity: {severity}\n"
        f"File: {file_path}:{line or 1}\n"
        f"Rule ID: {rule_id}\n"
        f"Vulnerable Code Snippet:\n```\n{code_snippet or 'N/A'}\n```\n\n"
        "Analyze this SAST vulnerability and produce a JSON response with fields:\n"
        "title, summary, technical_explanation, attack_scenario, business_impact, "
        "risk_level, confidence, cvss_estimate, cwe, owasp, mitre_attack, "
        "recommendation, secure_example, references."
    )
