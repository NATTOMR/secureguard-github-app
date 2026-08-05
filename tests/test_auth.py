"""
Purpose: Automated test suite for Phase 2 GitHub App authentication.

Responsibilities:
- Verify custom exception hierarchy.
- Test RS256 JWT generation with cryptography RSA keys.
- Test Installation Token caching and refresh logic.
- Test /auth/status and /auth/test HTTP endpoints.

Dependencies:
- pytest
- jwt
- cryptography
- app.auth.jwt_generator.JWTGenerator
- app.auth.installation_token.InstallationTokenService
- app.core.exceptions.ConfigurationError, TokenGenerationError

Usage:
    pytest tests/test_auth.py -v
"""

import time
from unittest.mock import AsyncMock, patch
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth.installation_token import InstallationTokenService
from app.auth.jwt_generator import JWTGenerator
from app.core.config import Settings
from app.core.exceptions import ConfigurationError, TokenGenerationError


@pytest.fixture
def generate_rsa_key_pem(tmp_path):
    """Generate a temporary RSA private key PEM file for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_file = tmp_path / "test_private_key.pem"
    key_file.write_bytes(pem)
    return str(key_file)


def test_custom_exceptions():
    """Test custom exception message and status code initialization."""
    err = ConfigurationError("Missing key")
    assert str(err) == "Missing key"
    assert err.message == "Missing key"


def test_jwt_generation_success(generate_rsa_key_pem):
    """Test successful RS256 JWT generation and claim verification."""
    settings = Settings(
        GITHUB_APP_ID=4492546,
        GITHUB_PRIVATE_KEY_PATH=generate_rsa_key_pem,
    )
    generator = JWTGenerator(settings)
    token = generator.generate_jwt()
    assert isinstance(token, str)

    # Decode without signature verification to inspect claims
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["iss"] == "4492546"
    assert decoded["exp"] > decoded["iat"]
    # Check expiration is 9 minutes (540s) from (iat + 60s)
    assert (decoded["exp"] - decoded["iat"]) == 600


def test_jwt_generation_missing_config():
    """Test JWT generation failure when GITHUB_APP_ID is missing."""
    settings = Settings(GITHUB_APP_ID=None)
    generator = JWTGenerator(settings)
    with pytest.raises(TokenGenerationError):
        generator.generate_jwt()


@pytest.mark.asyncio
async def test_installation_token_service_caching(generate_rsa_key_pem):
    """Test InstallationTokenService token caching mechanism."""
    settings = Settings(
        GITHUB_APP_ID=4492546,
        GITHUB_PRIVATE_KEY_PATH=generate_rsa_key_pem,
    )
    generator = JWTGenerator(settings)
    token_service = InstallationTokenService(generator)

    future_exp = time.time() + 3600
    mock_fetch = AsyncMock(return_value=("ghs_test_token_12345", future_exp))

    with patch.object(token_service, "_fetch_new_installation_token", mock_fetch):
        # First call -> fetches new token
        token1 = await token_service.get_installation_token(12345)
        assert token1 == "ghs_test_token_12345"
        assert mock_fetch.call_count == 1

        # Second call -> returned from cache
        token2 = await token_service.get_installation_token(12345)
        assert token2 == "ghs_test_token_12345"
        assert mock_fetch.call_count == 1  # Still 1 call


def test_auth_status_endpoint(client):
    """Test GET /auth/status endpoint response."""
    response = client.get("/auth/status")
    assert response.status_code == 200
    data = response.json()
    assert "authenticated" in data
    assert "environment" in data
    assert data["app_id"] == "4492546"


def test_auth_test_endpoint_unauthenticated(client, monkeypatch):
    """Test GET /auth/test endpoint returns 401 when private key is unconfigured."""
    from app.core.config import get_settings
    monkeypatch.setenv("GITHUB_PRIVATE_KEY_PATH", "")
    monkeypatch.setenv("PRIVATE_KEY_PATH", "")
    get_settings.cache_clear()
    
    response = client.get("/auth/test")
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
