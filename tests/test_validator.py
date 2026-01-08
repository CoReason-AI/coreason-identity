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
    TokenExpiredError,
)
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestTokenValidator:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        return Mock(spec=OIDCProvider)

    @pytest.fixture
    def key_pair(self) -> Any:
        # Generate a key pair for testing
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

    def test_validate_token_success(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "exp": now + 3600,
            "iat": now,
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        result = validator.validate_token(token_str)

        assert result["sub"] == "user123"
        assert result["aud"] == "my-audience"
        mock_oidc_provider.get_jwks.assert_called_once()

    def test_validate_token_expired(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "exp": now - 3600,  # Expired
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        with pytest.raises(TokenExpiredError, match="Token has expired"):
            validator.validate_token(token_str)

    def test_validate_token_invalid_audience(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "wrong-audience",
            "exp": now + 3600,
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        with pytest.raises(InvalidAudienceError, match="Invalid audience"):
            validator.validate_token(token_str)

    def test_validate_token_bad_signature(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "exp": now + 3600,
        }
        # Sign with a different key
        other_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        # Use KID of expected key but sign with other key
        headers = {"alg": "RS256", "kid": key_pair.as_dict()["kid"]}
        token = jwt.encode(headers, claims, other_key)
        token_str = token.decode("utf-8")

        with pytest.raises(SignatureVerificationError, match="Invalid signature"):
            validator.validate_token(token_str)

    def test_validate_token_malformed(
        self, validator: TokenValidator, mock_oidc_provider: Mock, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        token_str = "not.a.valid.token"

        with pytest.raises(CoreasonIdentityError, match="Token validation failed"):
            validator.validate_token(token_str)

    def test_validate_token_missing_claim(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            # Missing aud
            "exp": now + 3600,
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        with pytest.raises(CoreasonIdentityError, match="Missing claim"):
            validator.validate_token(token_str)

    def test_validate_token_issuer_check(self, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]) -> None:
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="my-audience", issuer="my-issuer")
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "wrong-issuer",
            "exp": now + 3600,
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            validator.validate_token(token_str)

    def test_validate_token_unexpected_error(self, validator: TokenValidator, mock_oidc_provider: Mock) -> None:
        # Mocking get_jwks to raise an unexpected exception
        mock_oidc_provider.get_jwks.side_effect = Exception("Boom")

        with pytest.raises(CoreasonIdentityError, match="Unexpected error"):
            validator.validate_token("some.token")
