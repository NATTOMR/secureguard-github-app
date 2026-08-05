"""
Purpose: General helper utilities.

Responsibilities:
- Provide common helper functions used across modules.

Dependencies:
- re
- typing.Any

Usage:
    clean_text = sanitize_string("input")
"""

import re


def sanitize_string(value: str) -> str:
    """Sanitize string by stripping control characters."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", value).strip()
