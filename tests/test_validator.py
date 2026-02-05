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
from unittest.mock import AsyncMock, Mock

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
        # Mock OIDCProvider with async get_jwks and get_issuer
        provider = Mock(spec=OIDCProvider)
        provider.get_jwks = AsyncMock()
        provider.get_issuer = AsyncMock(return_value="https://valid-issuer.com")
        return provider

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

    @pytest.mark.asyncio
    async def test_validate_token_success(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now + 3600,
            "iat": now,
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        result = await validator.validate_token(token_str)

        assert result["sub"] == "user123"
        assert result["aud"] == "my-audience"
        mock_oidc_provider.get_jwks.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_validate_token_expired(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now - 3600,  # Expired
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        with pytest.raises(TokenExpiredError, match="Token has expired"):
            await validator.validate_token(token_str)

    @pytest.mark.asyncio
    async def test_validate_token_invalid_audience(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "wrong-audience",
            "iss": "https://valid-issuer.com",
            "exp": now + 3600,
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        with pytest.raises(InvalidAudienceError, match="Invalid audience"):
            await validator.validate_token(token_str)

    @pytest.mark.asyncio
    async def test_validate_token_bad_signature(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now + 3600,
        }
        # Sign with a different key
        other_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        # Use KID of expected key but sign with other key
        headers = {"alg": "RS256", "kid": key_pair.as_dict()["kid"]}
        token = jwt.encode(headers, claims, other_key)
        token_str = token.decode("utf-8")

        # Mocking get_jwks to return valid keys, and forcing retry call if needed
        # TokenValidator logic: if verify fails, it refreshes keys.
        # So get_jwks might be called twice.

        with pytest.raises(SignatureVerificationError, match="Invalid signature"):
            await validator.validate_token(token_str)

    @pytest.mark.asyncio
    async def test_validate_token_malformed(
        self, validator: TokenValidator, mock_oidc_provider: Mock, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        token_str = "not.a.valid.token"

        with pytest.raises(CoreasonIdentityError, match="Token validation failed"):
            await validator.validate_token(token_str)

    @pytest.mark.asyncio
    async def test_validate_token_missing_claim(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user123",
            # Missing aud
            "iss": "https://valid-issuer.com",
            "exp": now + 3600,
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        with pytest.raises(CoreasonIdentityError, match="Missing claim"):
            await validator.validate_token(token_str)

    @pytest.mark.asyncio
    async def test_validate_token_issuer_check(
        self, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
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
            await validator.validate_token(token_str)

    @pytest.mark.asyncio
    async def test_validate_token_unexpected_error(self, validator: TokenValidator, mock_oidc_provider: Mock) -> None:
        # Mocking get_jwks to raise an unexpected exception
        mock_oidc_provider.get_jwks.side_effect = Exception("Boom")

        with pytest.raises(CoreasonIdentityError, match="Unexpected error"):
            await validator.validate_token("some.token")
