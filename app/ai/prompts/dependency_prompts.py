"""
Purpose: Specialized AI Prompt Builder for Dependency SCA Findings.
"""

from typing import Optional


def build_dependency_prompt(
    title: str,
    severity: str,
    file_path: str,
    line: Optional[int],
    rule_id: str,
    code_snippet: Optional[str] = None,
) -> str:
    """Build prompt tailored for Software Composition Analysis (SCA) vulnerabilities."""
    return (
        f"Category: DEPENDENCY_VULNERABILITY\n"
        f"Finding: {title}\n"
        f"Severity: {severity}\n"
        f"Manifest File: {file_path}\n"
        f"CVE/Rule ID: {rule_id}\n"
        f"Package Reference: {code_snippet or 'N/A'}\n\n"
        "Analyze this dependency vulnerability and produce a JSON response with fields:\n"
        "title, summary, technical_explanation, attack_scenario, business_impact, "
        "risk_level, confidence, cvss_estimate, cwe, owasp, mitre_attack, "
        "recommendation, secure_example, references."
    )
