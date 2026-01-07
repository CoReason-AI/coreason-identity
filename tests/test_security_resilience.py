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
from typing import List, Generator
from unittest.mock import MagicMock, patch

import pytest
from authlib.jose.errors import InvalidClaimError

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.exceptions import InvalidAudienceError
from coreason_identity.manager import IdentityManager
from coreason_identity.utils.logger import logger


@pytest.fixture
def mock_config() -> CoreasonIdentityConfig:
    return CoreasonIdentityConfig(
        domain="auth.coreason.com",
        audience="expected-audience",
        client_id="test-client",
    )


@pytest.fixture
def identity_manager(mock_config: CoreasonIdentityConfig) -> IdentityManager:
    # We patch OIDCProvider to avoid network calls during init
    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
        patch("coreason_identity.manager.IdentityMapper"),
    ):
        manager = IdentityManager(mock_config)
        # We need to re-attach the mock validator instance to be accessible in tests
        manager.validator = MockValidator.return_value  # type: ignore
        return manager


@pytest.fixture
def log_capture() -> Generator[List[str], None, None]:
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
    identity_manager.validator.validate_token.side_effect = InvalidAudienceError("Invalid audience")

    with pytest.raises(InvalidAudienceError) as exc_info:
        identity_manager.validate_token(f"Bearer {token}")

    assert "Invalid audience" in str(exc_info.value)


def test_audience_mismatch_real_validator_behavior() -> None:
    """
    Security Verification (Deep):
    Test that the TokenValidator logic actually identifies the mismatch
    by mocking the underlying jwt.decode behavior to raise InvalidClaimError('aud').
    """
    from coreason_identity.validator import TokenValidator

    mock_oidc = MagicMock()
    validator = TokenValidator(mock_oidc, audience="expected-audience")

    # Mock the internal jwt.decode to raise InvalidClaimError for 'aud'
    with patch.object(validator.jwt, "decode") as mock_decode:
        mock_claims = MagicMock()
        mock_claims.validate.side_effect = InvalidClaimError("aud")
        mock_decode.return_value = mock_claims

        # We also need to mock get_jwks to return something so it proceeds to decode
        mock_oidc.get_jwks.return_value = {"keys": []}

        with pytest.raises(InvalidAudienceError) as exc_info:
            validator.validate_token("some.token")

        assert "Invalid audience" in str(exc_info.value)


def test_pii_redaction_in_logs(identity_manager: IdentityManager, log_capture: List[str]) -> None:
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
    expected_hash = hashlib.sha256(sensitive_user_id.encode("utf-8")).hexdigest()

    # Mock validation success on the identity manager itself won't trigger the logging code
    # inside Validator. We need to construct a real Validator or use the one we construct below.

    from coreason_identity.validator import TokenValidator
    from coreason_identity.oidc_provider import OIDCProvider

    mock_oidc = MagicMock(spec=OIDCProvider)
    mock_oidc.get_jwks.return_value = {"keys": []}

    validator = TokenValidator(mock_oidc, audience="aud")

    # Mock jwt.decode to return our claims without error
    with patch.object(validator.jwt, "decode") as mock_decode:
        # Mock claims dict
        mock_claims_dict = {"sub": sensitive_user_id, "aud": "aud", "exp": 1234567890}

        # We need an object that mimics the Authlib claims object:
        # 1. It must be iterable (yields keys)
        # 2. It must have .validate()
        # 3. dict(claims) must work

        class MockClaims(dict):
            def validate(self):
                pass

        claims_obj = MockClaims(mock_claims_dict)
        mock_decode.return_value = claims_obj

        validator.validate_token(token_string)

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
