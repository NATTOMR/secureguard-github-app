"""
Purpose: Risk scoring engine and compliance mapper for SecureGuard.

Responsibilities:
- Calculate Technical Risk, Business Risk, Overall Risk Score, CVSS estimate, Exploitability, Impact, and Confidence.
- Map rule IDs and findings to CWE, OWASP Top 10, MITRE ATT&CK, and NIST CSF frameworks.

Dependencies:
- typing.Dict, Any, Optional
- app.models.scan_result.Finding

Usage:
    risk_engine = RiskEngine()
    score_card = risk_engine.evaluate_risk(rule_id="aws-access-key", severity="CRITICAL")
"""

from typing import Any, Dict, Optional


class RiskEngine:
    """Risk scoring engine and compliance mapping module."""

    CWE_MAP = {
        "aws-access-key": "CWE-798: Use of Hard-coded Credentials",
        "github-token": "CWE-798: Use of Hard-coded Credentials",
        "env-secret": "CWE-538: Insertion of Sensitive Information into Externally-Accessible File",
        "python-eval": "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
        "python-exec": "CWE-94: Improper Control of Generation of Code ('Code Injection')",
        "python-pickle": "CWE-502: Deserialization of Untrusted Data",
        "python-subprocess-shell": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "js-eval": "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
        "js-innerhtml-xss": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    }

    OWASP_MAP = {
        "aws-access-key": "A07:2021-Identification and Authentication Failures",
        "github-token": "A07:2021-Identification and Authentication Failures",
        "env-secret": "A01:2021-Broken Access Control",
        "python-eval": "A03:2021-Injection",
        "python-exec": "A03:2021-Injection",
        "python-pickle": "A08:2021-Software and Data Integrity Failures",
        "python-subprocess-shell": "A03:2021-Injection",
        "js-eval": "A03:2021-Injection",
        "js-innerhtml-xss": "A03:2021-Injection",
    }

    MITRE_MAP = {
        "aws-access-key": "T1552.001: Unsecured Credentials - Credentials In Files",
        "github-token": "T1552.001: Unsecured Credentials - Credentials In Files",
        "python-eval": "T1059: Command and Scripting Interpreter",
        "python-subprocess-shell": "T1059.004: Command and Scripting Interpreter - Unix Shell",
        "js-innerhtml-xss": "T1189: Drive-by Compromise",
    }

    NIST_MAP = {
        "CRITICAL": "NIST CSF PR.AC-1: Access Control",
        "HIGH": "NIST CSF PR.DS-5: Data Security",
        "MEDIUM": "NIST CSF DE.CM-1: Continuous Monitoring",
        "LOW": "NIST CSF PR.IP-1: Information Protection",
    }

    def evaluate_risk(self, rule_id: str, severity: str) -> Dict[str, Any]:
        """Compute technical risk, business risk, CVSS score estimate, and compliance mappings."""
        sev_upper = severity.upper()

        if sev_upper == "CRITICAL":
            cvss = 9.8
            exploitability = 9.0
            impact = 10.0
            tech_risk = "CRITICAL"
            biz_risk = "HIGH"
            priority = "P0 - Immediate Fix Required"
        elif sev_upper == "HIGH":
            cvss = 8.5
            exploitability = 8.0
            impact = 8.5
            tech_risk = "HIGH"
            biz_risk = "HIGH"
            priority = "P1 - Fix in Current Sprint"
        elif sev_upper == "MEDIUM":
            cvss = 6.5
            exploitability = 6.0
            impact = 6.5
            tech_risk = "MEDIUM"
            biz_risk = "MODERATE"
            priority = "P2 - Fix in Next Release"
        else:
            cvss = 3.5
            exploitability = 4.0
            impact = 3.0
            tech_risk = "LOW"
            biz_risk = "LOW"
            priority = "P3 - Backlog Advisory"

        overall_score = round(cvss * 10, 1)

        cwe = self.CWE_MAP.get(rule_id, "CWE-200: Exposure of Sensitive Information")
        owasp = self.OWASP_MAP.get(rule_id, "A03:2021-Injection")
        mitre = self.MITRE_MAP.get(rule_id, "T1059: Command and Scripting Interpreter")
        nist = self.NIST_MAP.get(sev_upper, "NIST CSF PR.DS-5: Data Security")

        return {
            "technical_risk": tech_risk,
            "business_risk": biz_risk,
            "overall_risk_score": overall_score,
            "priority": priority,
            "cvss_estimate": cvss,
            "exploitability": exploitability,
            "impact": impact,
            "confidence": "HIGH",
            "cwe": cwe,
            "owasp": owasp,
            "mitre_attack": mitre,
            "nist_csf": nist,
        }
