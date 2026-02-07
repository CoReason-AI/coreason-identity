# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import hashlib
import hmac
from collections.abc import Generator
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from authlib.jose.errors import InvalidClaimError

from coreason_identity.config import CoreasonVerifierConfig
from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InvalidAudienceError,
    InvalidTokenError,
)
from coreason_identity.manager import IdentityManager
from coreason_identity.utils.logger import logger


@pytest.fixture
def mock_config() -> CoreasonVerifierConfig:
    return CoreasonVerifierConfig(
        domain="auth.coreason.com",
        audience="expected-audience",
    )


@pytest.fixture
def identity_manager(mock_config: CoreasonVerifierConfig) -> Generator[IdentityManager, Any, None]:
    # We patch OIDCProvider to avoid network calls during init
    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
    ):
        manager = IdentityManager(mock_config)
        yield manager


@pytest.fixture
def log_capture() -> Generator[list[str], None, None]:
    """Fixture to capture loguru logs."""
    logs = []
    # Add a sink that appends the formatted message to the list
    handler_id = logger.add(lambda msg: logs.append(msg), format="{message}", level="INFO")
    yield logs
    logger.remove(handler_id)


def test_audience_mismatch_rejection(identity_manager: IdentityManager) -> None:
    """
    Security Verification:
    Verify that an audience mismatch triggers an InvalidAudienceError.
    This protects against Confused Deputy attacks.
    """
    token = "some.jwt.token"

    # Configure the mock validator to raise InvalidAudienceError
    # Access via _async since IdentityManager is facade
    mock_validator = cast("MagicMock", identity_manager._async.validator)
    # validate_token is async
    mock_validator.validate_token = AsyncMock(side_effect=InvalidAudienceError("Invalid audience"))

    with pytest.raises(InvalidAudienceError) as exc_info:
        identity_manager.validate_token(f"Bearer {token}")

    assert "Invalid audience" in str(exc_info.value)


@pytest.mark.asyncio
async def test_audience_mismatch_real_validator_behavior() -> None:
    """
    Security Verification (Deep):
    Test that the TokenValidator logic actually identifies the mismatch
    by mocking the underlying jwt.decode behavior to raise InvalidClaimError('aud').
    """
    from coreason_identity.validator import TokenValidator

    mock_oidc = MagicMock()
    mock_oidc.get_jwks = AsyncMock(return_value={"keys": []})
    mock_oidc.get_issuer = AsyncMock(return_value="https://issuer.com")
    validator = TokenValidator(mock_oidc, audience="expected-audience", issuer="https://issuer.com")

    # Mock the internal jwt.decode to raise InvalidClaimError for 'aud'
    with patch.object(validator.jwt, "decode") as mock_decode:
        mock_claims = MagicMock()
        mock_claims.validate.side_effect = InvalidClaimError("aud")
        mock_decode.return_value = mock_claims

        with pytest.raises(InvalidAudienceError) as exc_info:
            await validator.validate_token("some.token")

        assert "Invalid audience" in str(exc_info.value)


@pytest.mark.asyncio
async def test_pii_redaction_in_logs(log_capture: list[str]) -> None:
    """
    Security Verification:
    Verify that PII (User ID) is never logged in plaintext.
    Verify that the Token itself is never logged.
    Verify that the hashed User ID is logged.
    """
    # Setup
    sensitive_user_id = "user_sensitive_12345"
    token_string = "sensitive.jwt.token.string"

    # Compute expected hash
    expected_hash = hmac.new(
        b"coreason-unsafe-default-salt", sensitive_user_id.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # Mock validation success on the identity manager itself won't trigger the logging code
    # inside Validator. We need to construct a real Validator or use the one we construct below.

    from coreason_identity.oidc_provider import OIDCProvider
    from coreason_identity.validator import TokenValidator

    mock_oidc = MagicMock(spec=OIDCProvider)
    mock_oidc.get_jwks = AsyncMock(return_value={"keys": []})
    mock_oidc.get_issuer = AsyncMock(return_value="https://issuer.com")

    validator = TokenValidator(mock_oidc, audience="aud", issuer="https://issuer.com")

    # Mock jwt.decode to return our claims without error
    with patch.object(validator.jwt, "decode") as mock_decode:
        # Mock claims dict
        mock_claims_dict = {"sub": sensitive_user_id, "aud": "aud", "exp": 1234567890}

        # We need an object that mimics the Authlib claims object:
        # 1. It must be iterable (yields keys)
        # 2. It must have .validate()
        # 3. dict(claims) must work

        class MockClaims(dict[str, Any]):
            def validate(self, *args: Any, **kwargs: Any) -> None:
                pass

        claims_obj = MockClaims(mock_claims_dict)
        mock_decode.return_value = claims_obj

        await validator.validate_token(token_string)

        # Join logs to search
        full_log_text = "\n".join(log_capture)

        # Assertions

        # 1. Token string not logged
        assert token_string not in full_log_text, "FATAL: Raw token found in logs!"

        # 2. Raw User ID not logged
        assert sensitive_user_id not in full_log_text, "FATAL: Raw PII (sub) found in logs!"

        # 3. Hashed User ID IS logged
        assert expected_hash in full_log_text, "Expected hashed user ID not found in logs."

        # 4. Specific message format check (fuzzy match)
        assert f"Token validated for user {expected_hash}" in full_log_text


class TestSecurityEdgeCases:
    """
    Additional complex and edge case tests for security resilience.
    """

    def test_malformed_token_formats(self, identity_manager: IdentityManager) -> None:
        """
        AuthN Edge Case: Verify rejection of invalid Authorization header formats.
        """
        # 1. Missing header (empty string passed to manager)
        with pytest.raises(InvalidTokenError, match="Missing Authorization header"):
            identity_manager.validate_token("")

        # 2. "Bearer" only (no token)
        with pytest.raises(InvalidTokenError, match="Invalid Authorization header format"):
            identity_manager.validate_token("Bearer")

        # 3. "Bearer " only (empty token)
        # Now rejected by Manager regex
        with pytest.raises(InvalidTokenError, match="Invalid Authorization header format"):
            identity_manager.validate_token("Bearer ")

        # 4. Wrong scheme "Basic"
        with pytest.raises(InvalidTokenError, match="Must start with 'Bearer '"):
            identity_manager.validate_token("Basic dXNlcjpwYXNz")

        # 5. Wrong scheme "Token"
        with pytest.raises(InvalidTokenError, match="Must start with 'Bearer '"):
            identity_manager.validate_token("Token 123")

    def test_jwks_fetch_failure(self, identity_manager: IdentityManager) -> None:
        """
        Resilience Edge Case: Verify behavior when JWKS cannot be fetched (e.g., IdP down).
        """
        mock_validator = cast("MagicMock", identity_manager._async.validator)
        mock_validator.validate_token = AsyncMock(side_effect=CoreasonIdentityError("Failed to fetch JWKS"))

        with pytest.raises(CoreasonIdentityError, match="Failed to fetch JWKS"):
            identity_manager.validate_token("Bearer token")

    @pytest.mark.asyncio
    async def test_unicode_pii_logging(self, log_capture: list[str]) -> None:
        """
        Logging Edge Case: Verify that Unicode characters in PII are handled and hashed correctly.
        """
        unicode_user_id = "user_🚀_ñ_123"
        expected_hash = hmac.new(
            b"coreason-unsafe-default-salt", unicode_user_id.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        token_string = "unicode.jwt.token"

        from coreason_identity.oidc_provider import OIDCProvider
        from coreason_identity.validator import TokenValidator

        mock_oidc = MagicMock(spec=OIDCProvider)
        mock_oidc.get_jwks = AsyncMock(return_value={"keys": []})
        mock_oidc.get_issuer = AsyncMock(return_value="https://issuer.com")

        validator = TokenValidator(mock_oidc, audience="aud", issuer="https://issuer.com")

        with patch.object(validator.jwt, "decode") as mock_decode:
            mock_claims_dict = {"sub": unicode_user_id, "aud": "aud", "exp": 1234567890}

            class MockClaims(dict[str, Any]):
                def validate(self, *args: Any, **kwargs: Any) -> None:
                    pass

            mock_decode.return_value = MockClaims(mock_claims_dict)

            await validator.validate_token(token_string)

            full_log_text = "\n".join(log_capture)

            assert unicode_user_id not in full_log_text
            assert expected_hash in full_log_text
