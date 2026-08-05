"""
Purpose: Prompt template builder for SecureGuard AI Security Assistant.

Responsibilities:
- Format structured prompts for vulnerability analysis, secure code generation, risk scoring, and security chat assistant conversations.

Dependencies:
- typing.Dict, Any, Optional

Usage:
    builder = PromptBuilder()
    prompt = builder.build_vulnerability_prompt(title="...", severity="...", code_snippet="...")
"""

from typing import Any, Dict, Optional


class PromptBuilder:
    """Builder for structured security prompts."""

    @staticmethod
    def build_system_prompt() -> str:
        """Return global system prompt for AI Security Assistant."""
        return (
            "You are a Senior Principal Application Security Architect for SecureGuard. "
            "Your objective is to provide concise, enterprise-grade security analysis, attack scenarios, "
            "CVSS/CWE/OWASP mappings, and safe code remediations."
        )

    @staticmethod
    def build_vulnerability_prompt(
        title: str,
        severity: str,
        file_path: str,
        line: Optional[int],
        rule_id: str,
        code_snippet: Optional[str] = None,
    ) -> str:
        """Build structured vulnerability analysis prompt."""
        lines = [
            f"Analyze the following security finding:",
            f"- Title: {title}",
            f"- Severity: {severity}",
            f"- File: {file_path}",
            f"- Line: {line or 'N/A'}",
            f"- Rule: {rule_id}",
        ]
        if code_snippet:
            lines.append(f"- Code Snippet:\n```\n{code_snippet}\n```")

        lines.append(
            "\nPlease provide:\n"
            "1. Detailed Explanation\n"
            "2. Attack Scenario\n"
            "3. Business Impact\n"
            "4. CVSS Estimate & CWE Mapping\n"
            "5. OWASP Top 10 Mapping\n"
            "6. Actionable Recommendation"
        )
        return "\n".join(lines)

    @staticmethod
    def build_fix_prompt(
        vulnerable_code: str,
        language: str = "python",
        rule_id: Optional[str] = None,
    ) -> str:
        """Build secure code fix generation prompt."""
        return (
            f"Language: {language}\n"
            f"Rule Triggered: {rule_id or 'security-risk'}\n"
            f"Vulnerable Code:\n```\n{vulnerable_code}\n```\n\n"
            "Please generate:\n"
            "1. Fixed Secure Code\n"
            "2. Explanation of Fix\n"
            "3. Why this solution is secure"
        )

    @staticmethod
    def build_chat_prompt(user_message: str, context: Optional[str] = None) -> str:
        """Build interactive chat assistant prompt."""
        if context:
            return f"Context:\n{context}\n\nUser Question: {user_message}"
        return f"User Question: {user_message}"
