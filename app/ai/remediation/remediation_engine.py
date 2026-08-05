"""
Purpose: Remediation Engine orchestrator for SecureGuard.

Responsibilities:
- Combine LanguageDetector, SecureCodeGenerator, PatchBuilder, CodeValidator, and ConfidenceEngine.
- Formulate exact output schema matching RemediationResponse contract.

Dependencies:
- typing.Dict, Any, Optional
- app.ai.remediation.language_detector.LanguageDetector
- app.ai.remediation.code_generator.SecureCodeGenerator
- app.ai.remediation.patch_builder.PatchBuilder
- app.ai.remediation.validator.CodeValidator
- app.ai.remediation.confidence_engine.ConfidenceEngine

Usage:
    engine = RemediationEngine()
    result = engine.generate_remediation(vulnerable_code="...", filename="app.py", rule_id="...")
"""

from typing import Any, Dict, Optional

from app.ai.remediation.code_generator import SecureCodeGenerator
from app.ai.remediation.confidence_engine import ConfidenceEngine
from app.ai.remediation.language_detector import LanguageDetector
from app.ai.remediation.patch_builder import PatchBuilder
from app.ai.remediation.validator import CodeValidator


class RemediationEngine:
    """Orchestrator for AI Secure Code Remediation."""

    def __init__(self) -> None:
        self.language_detector = LanguageDetector()
        self.code_generator = SecureCodeGenerator()
        self.patch_builder = PatchBuilder()
        self.validator = CodeValidator()
        self.confidence_engine = ConfidenceEngine()

    def generate_remediation(
        self,
        vulnerable_code: str,
        language: Optional[str] = None,
        rule_id: str = "security-finding",
        filename: str = "vulnerable.py",
        severity: str = "HIGH",
    ) -> Dict[str, Any]:
        """Generate comprehensive secure code remediation payload."""
        # 1. Detect target language
        target_lang = language or self.language_detector.detect(filename, vulnerable_code)

        # 2. Generate secure code replacement
        gen_data = self.code_generator.generate(vulnerable_code, target_lang, rule_id)
        secure_code = gen_data["secure_code"]

        # 3. Validate syntax correctness
        is_valid = self.validator.validate_code(secure_code, target_lang)

        # 4. Generate unified diff and git patch
        diff_text = self.patch_builder.build_unified_diff(vulnerable_code, secure_code, filename)
        patch_text = f"--- a/{filename}\n+++ b/{filename}\n{diff_text}"

        # 5. Evaluate confidence & risk metrics
        confidence_data = self.confidence_engine.evaluate(rule_id, target_lang)

        return {
            "language": target_lang,
            "vulnerability": gen_data["vulnerability"],
            "severity": severity,
            "confidence": confidence_data["confidence"],
            "summary": gen_data["summary"],
            "reasoning": gen_data["reasoning"],
            "original_code": vulnerable_code,
            "secure_code": secure_code,
            "diff": diff_text,
            "patch": patch_text,
            "breaking_change": confidence_data["breaking_change"],
            "manual_review_required": confidence_data["manual_review_required"],
            "recommendation": gen_data["recommendation"],
            "references": [
                "https://owasp.org/www-project-top-ten/",
                "https://cwe.mitre.org/",
            ],
        }
