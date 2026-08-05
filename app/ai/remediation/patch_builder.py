"""
Purpose: Patch builder module for generating Unified Diffs, Git Patches, and GitHub PR suggestions.

Responsibilities:
- Build clean unified git diffs, git patches, and Markdown suggestion blocks.

Dependencies:
- difflib.unified_diff
- typing.Dict, Any
"""

import difflib
from typing import Dict


class PatchBuilder:
    """Builder for Unified Diffs, Git Patches, and PR suggestion blocks."""

    @staticmethod
    def build_unified_diff(original: str, fixed: str, filename: str = "vulnerable.py") -> str:
        """Generate unified git diff."""
        orig_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)

        diff = difflib.unified_diff(
            orig_lines,
            fixed_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
        return "".join(diff) or f"- {original}\n+ {fixed}"

    @staticmethod
    def build_pr_suggestion(fixed_code: str) -> str:
        """Generate GitHub PR suggestion block."""
        return f"```suggestion\n{fixed_code}\n```"
