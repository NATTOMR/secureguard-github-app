"""
Purpose: Remediation generator module for SecureGuard AI Assistant.

Responsibilities:
- Generate fixed secure code examples and explanations for Python, JS, TS, Go, Java, Docker, and Terraform.

Dependencies:
- typing.Dict, Any, Optional
- app.ai.llm_client.LLMClient
- app.ai.prompt_builder.PromptBuilder

Usage:
    generator = RemediationGenerator()
    remediation = await generator.generate_fix(vulnerable_code="...", language="python", rule_id="python-eval")
"""

from typing import Any, Dict, Optional

from app.ai.llm_client import LLMClient
from app.ai.prompt_builder import PromptBuilder


class RemediationGenerator:
    """Module generating secure code remediations across supported languages."""

    def __init__(self, llm_client: Optional[LLMClient] = None) -> None:
        self.llm_client = llm_client or LLMClient()
        self.prompt_builder = PromptBuilder()

    async def generate_fix(
        self,
        vulnerable_code: str,
        language: str = "python",
        rule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate secure fix and explanation."""
        lang_lower = language.lower()

        # Rule-based fast remediations for standard patterns
        if "eval(" in vulnerable_code or "exec(" in vulnerable_code:
            fixed_code = "# Secure Replacement: Use safe literal evaluation or explicit mapping\nimport ast\nvalue = ast.literal_eval(user_input)"
            explanation = "Replaced dangerous eval() with ast.literal_eval() to safely parse literals without code execution."
            why_secure = "ast.literal_eval only evaluates Python literals (strings, numbers, tuples, lists, dicts, booleans, and None) and rejects executable logic."
        elif "sk_test_" in vulnerable_code or "AKIA" in vulnerable_code or "token" in vulnerable_code.lower():
            fixed_code = "# Secure Replacement: Fetch secret from environment variable\nimport os\napi_key = os.environ.get('API_SECRET_KEY')"
            explanation = "Removed hardcoded secret string and replaced with dynamic environment variable lookup."
            why_secure = "Environment variables prevent sensitive credentials from leaking into git repositories and version history."
        elif "shell=true" in vulnerable_code.lower():
            fixed_code = "# Secure Replacement: Pass arguments as list without shell=True\nimport subprocess\nsubprocess.run(['ls', '-l'], check=True)"
            explanation = "Removed shell=True and passed command arguments as an array list."
            why_secure = "Passing command arguments as a list bypasses the shell parser, rendering shell injection attacks impossible."
        else:
            prompt = self.prompt_builder.build_fix_prompt(vulnerable_code, language, rule_id)
            ai_response = await self.llm_client.generate(prompt, self.prompt_builder.build_system_prompt())
            fixed_code = f"// Secure Fix ({language})\n// Review AI guidance\n{ai_response}"
            explanation = "AI-generated secure code refactoring."
            why_secure = "Enforces least privilege and secure input handling."

        return {
            "language": language,
            "rule_id": rule_id or "security-remediation",
            "vulnerable_code": vulnerable_code,
            "fixed_code": fixed_code,
            "explanation": explanation,
            "why_secure": why_secure,
        }
