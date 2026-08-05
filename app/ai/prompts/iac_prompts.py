"""
Purpose: Specialized AI Prompt Builder for Infrastructure as Code (IaC) Findings.
"""

from typing import Optional


def build_iac_prompt(
    title: str,
    severity: str,
    file_path: str,
    line: Optional[int],
    rule_id: str,
    code_snippet: Optional[str] = None,
) -> str:
    """Build prompt tailored for Terraform/CloudFormation IaC misconfigurations."""
    return (
        f"Category: IAC_MISCONFIGURATION\n"
        f"Finding: {title}\n"
        f"Severity: {severity}\n"
        f"IaC File: {file_path}:{line or 1}\n"
        f"Rule ID: {rule_id}\n"
        f"Config Snippet:\n```hcl\n{code_snippet or 'N/A'}\n```\n\n"
        "Analyze this IaC misconfiguration and produce a JSON response with fields:\n"
        "title, summary, technical_explanation, attack_scenario, business_impact, "
        "risk_level, confidence, cvss_estimate, cwe, owasp, mitre_attack, "
        "recommendation, secure_example, references."
    )
