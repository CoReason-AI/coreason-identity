# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import time
from typing import Any, Dict
from unittest.mock import Mock

import pytest
from authlib.jose import JsonWebKey, jwt
from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InvalidAudienceError,
    SignatureVerificationError,
)
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestTokenValidatorComplex:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        return Mock(spec=OIDCProvider)

    @pytest.fixture
    def key_pair(self) -> Any:
        # Generate a key pair for testing
        key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        return key

    @pytest.fixture
    def second_key_pair(self) -> Any:
        # Generate a second key pair for key rotation testing
        key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        return key

    @pytest.fixture
    def jwks(self, key_pair: Any) -> Dict[str, Any]:
        # Return public key in JWKS format
        return {"keys": [key_pair.as_dict(private=False)]}

    @pytest.fixture
    def validator(self, mock_oidc_provider: Mock) -> TokenValidator:
        return TokenValidator(oidc_provider=mock_oidc_provider, audience="my-audience")

    def create_token(self, key: Any, claims: Dict[str, Any], headers: Dict[str, Any] | None = None) -> bytes:
        if headers is None:
            headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
        return jwt.encode(headers, claims, key)  # type: ignore[no-any-return]

    def test_validate_token_aud_list_success(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        """Test that validation succeeds when aud is a list containing the expected audience."""
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": ["other-audience", "my-audience"],  # List with valid aud
            "exp": now + 3600,
            "iat": now,
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        result = validator.validate_token(token_str)
        assert result["sub"] == "user123"

    def test_validate_token_aud_list_fail(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        """Test that validation fails when aud is a list NOT containing the expected audience."""
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": ["other-audience", "another-one"],  # List without valid aud
            "exp": now + 3600,
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        with pytest.raises(InvalidAudienceError):
            validator.validate_token(token_str)

    def test_validate_token_whitespace(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        """Test that validation handles whitespace."""
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "exp": now + 3600,
        }
        token = self.create_token(key_pair, claims)
        token_str = "  " + token.decode("utf-8") + "  \n"

        # Current implementation might fail if it doesn't strip
        try:
            result = validator.validate_token(token_str)
            assert result["sub"] == "user123"
        except CoreasonIdentityError:
            pytest.fail("Should handle whitespace")

    def test_key_rotation_retry(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, second_key_pair: Any
    ) -> None:
        """
        Test key rotation scenario.
        1. Token is signed with `second_key_pair`.
        2. First `get_jwks()` returns only `key_pair`.
        3. Validation fails (unknown key).
        4. Validator should refresh keys.
        5. Second `get_jwks(force_refresh=True)` returns `second_key_pair`.
        6. Validation succeeds.
        """
        # First call returns old keys
        old_jwks = {"keys": [key_pair.as_dict(private=False)]}
        # Second call (after refresh) returns new keys including the one used for signing
        new_jwks = {"keys": [key_pair.as_dict(private=False), second_key_pair.as_dict(private=False)]}

        # We need to simulate the sequence of returns
        # The validator calls get_jwks() initially (defaults force_refresh=False)
        # If it fails, it calls get_jwks(force_refresh=True)

        def get_jwks_side_effect(force_refresh: bool = False) -> Dict[str, Any]:
            if force_refresh:
                return new_jwks
            return old_jwks

        mock_oidc_provider.get_jwks.side_effect = get_jwks_side_effect

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "exp": now + 3600,
        }
        # Sign with second key (which is missing in old_jwks)
        token = self.create_token(second_key_pair, claims)
        token_str = token.decode("utf-8")

        result = validator.validate_token(token_str)
        assert result["sub"] == "user123"

        # Verify call count
        # 1. get_jwks()
        # 2. get_jwks(force_refresh=True)
        assert mock_oidc_provider.get_jwks.call_count == 2
        mock_oidc_provider.get_jwks.assert_any_call(force_refresh=True)

    def test_none_algorithm_rejected(
        self, validator: TokenValidator, mock_oidc_provider: Mock, jwks: Dict[str, Any]
    ) -> None:
        """Test that alg: none is rejected."""
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "exp": now + 3600,
        }
        # Create a token with 'none' alg manually
        # Authlib's jwt.encode might block 'none' if not configured,
        # but we can construct the string manually or force it
        # header: {"alg": "none"} -> eyJhbGciOiJub25lIn0
        # payload: ...
        # signature: empty

        header_segment = "eyJhbGciOiJub25lIn0"  # {"alg":"none"}
        import base64
        import json

        payload_json = json.dumps(claims).encode()
        payload_segment = base64.urlsafe_b64encode(payload_json).rstrip(b"=").decode()

        token_str = f"{header_segment}.{payload_segment}."

        # This should fail validation
        with pytest.raises(CoreasonIdentityError):
            validator.validate_token(token_str)

    def test_key_missing_after_retry(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        """
        Test that if key is missing even after retry, it raises SignatureVerificationError.
        """
        # Mock get_jwks to always return keys that DO NOT include the signing key
        mock_oidc_provider.get_jwks.return_value = jwks

        # Sign with a new random key that is not in jwks
        unknown_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "exp": now + 3600,
        }
        token = self.create_token(unknown_key, claims)
        token_str = token.decode("utf-8")

        # It should try once, fail (ValueError), refresh, fail again (ValueError), then propagate
        with pytest.raises(SignatureVerificationError, match="Invalid signature or key not found"):
            validator.validate_token(token_str)

        assert mock_oidc_provider.get_jwks.call_count == 2
