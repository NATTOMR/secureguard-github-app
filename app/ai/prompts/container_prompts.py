"""
Purpose: Specialized AI Prompt Builder for Container Security Findings.
"""

from typing import Optional


def build_container_prompt(
    title: str,
    severity: str,
    file_path: str,
    line: Optional[int],
    rule_id: str,
    code_snippet: Optional[str] = None,
) -> str:
    """Build prompt tailored for Docker and Container image vulnerabilities."""
    return (
        f"Category: CONTAINER_SECURITY\n"
        f"Finding: {title}\n"
        f"Severity: {severity}\n"
        f"Dockerfile/Image: {file_path}\n"
        f"Rule ID: {rule_id}\n"
        f"Instruction Snippet: {code_snippet or 'N/A'}\n\n"
        "Analyze this container flaw and produce a JSON response with fields:\n"
        "title, summary, technical_explanation, attack_scenario, business_impact, "
        "risk_level, confidence, cvss_estimate, cwe, owasp, mitre_attack, "
        "recommendation, secure_example, references."
    )
