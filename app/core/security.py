"""
Purpose: Core security and credential handling utilities.

Responsibilities:
- Provide safe masking for sensitive tokens and keys in log messages.
- Read and validate RSA private key files for GitHub App JWT signing.

Dependencies:
- pathlib.Path
- cryptography.hazmat.primitives.serialization
- app.core.exceptions.ConfigurationError

Usage:
    from app.core.security import mask_secret, load_private_key

    masked = mask_secret("ghs_1234567890abcdef")
    key_bytes = load_private_key("path/to/key.pem")
"""

from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import serialization
from app.core.exceptions import ConfigurationError


def mask_secret(secret: Optional[str], visible_chars: int = 4) -> str:
    """Mask a sensitive token or key string showing only trailing characters."""
    if not secret:
        return "[NOT SET]"
    if len(secret) <= visible_chars:
        return "*" * len(secret)
    return "*" * (len(secret) - visible_chars) + secret[-visible_chars:]


def load_private_key(key_path_or_content: str) -> bytes:
    """Load and validate an RSA private key from file path or PEM content string."""
    if not key_path_or_content:
        raise ConfigurationError("Private key path or content is required.")

    # Check if input is a direct PEM string
    if "BEGIN" in key_path_or_content and "PRIVATE KEY" in key_path_or_content:
        key_bytes = key_path_or_content.encode("utf-8")
    else:
        path = Path(key_path_or_content)
        if not path.is_file():
            raise ConfigurationError(f"Private key file not found at path: {key_path_or_content}")
        try:
            key_bytes = path.read_bytes()
        except Exception as e:
            raise ConfigurationError(f"Failed to read private key file: {str(e)}")

    try:
        serialization.load_pem_private_key(key_bytes, password=None)
    except Exception as e:
        raise ConfigurationError(f"Invalid RSA private key format: {str(e)}")

    return key_bytes


def verify_webhook_signature(payload_bytes: bytes, signature_header: Optional[str], secret: str) -> bool:
    """Verify GitHub HMAC-SHA256 webhook signature (X-Hub-Signature-256)."""
    if not secret or not signature_header:
        # If no secret is configured, bypass signature check in dev mode
        return True
    
    if not signature_header.startswith("sha256="):
        return False
        
    expected_hash = signature_header[7:]
    import hmac
    import hashlib
    
    computed_hash = hmac.new(
        secret.encode("utf-8"),
        msg=payload_bytes,
        digestmod=hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(computed_hash, expected_hash)
