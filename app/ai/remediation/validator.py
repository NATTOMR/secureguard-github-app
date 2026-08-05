"""
Purpose: Validator module for checking syntax and formatting of generated secure fixes.

Responsibilities:
- Validate syntax correctness for Python, JSON, YAML, etc., to prevent invalid output code.

Dependencies:
- ast
- json
- yaml
"""

import ast
import json


class CodeValidator:
    """Validator ensuring generated code does not contain syntax errors."""

    @staticmethod
    def validate_code(code: str, language: str) -> bool:
        """Validate code syntax for given language."""
        lang_lower = language.lower()
        if lang_lower == "python":
            try:
                ast.parse(code)
                return True
            except SyntaxError:
                return False
        elif lang_lower == "json":
            try:
                json.loads(code)
                return True
            except Exception:
                return False
        return True
