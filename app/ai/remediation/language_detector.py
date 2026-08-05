"""
Purpose: Language detector module for SecureGuard Remediation Engine.

Responsibilities:
- Detect target language from filename or code snippet features.

Dependencies:
- typing.Optional
"""

from typing import Optional


class LanguageDetector:
    """Language detection helper."""

    EXT_MAP = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".cs": "csharp",
        "dockerfile": "dockerfile",
        ".tf": "terraform",
        ".yaml": "yaml",
        ".yml": "yaml",
    }

    @classmethod
    def detect(cls, filename: Optional[str] = None, code_snippet: Optional[str] = None) -> str:
        """Detect language from file extension or syntax features."""
        if filename:
            fn_lower = filename.lower()
            if "dockerfile" in fn_lower:
                return "dockerfile"
            for ext, lang in cls.EXT_MAP.items():
                if fn_lower.endswith(ext):
                    return lang

        if code_snippet:
            snippet = code_snippet.lower()
            if "package " in snippet and "import (" in snippet:
                return "go"
            elif "public class " in snippet or "system.out.println" in snippet:
                return "java"
            elif "using system;" in snippet or "namespace " in snippet:
                return "csharp"
            elif "from " in snippet and "import " in snippet:
                return "python"
            elif "resource \"" in snippet or "provider \"" in snippet:
                return "terraform"
            elif "from " in snippet and "run " in snippet:
                return "dockerfile"

        return "python"
