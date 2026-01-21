# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from typing import Any, Dict
from unittest.mock import AsyncMock, Mock

import pytest
from authlib.jose import JsonWebKey, jwt
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestTokenValidatorEdgeCases:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        provider = Mock(spec=OIDCProvider)
        provider.get_jwks = AsyncMock()
        return provider

    @pytest.fixture
    def key_pair(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @pytest.fixture
    def jwks(self, key_pair: Any) -> Dict[str, Any]:
        return {"keys": [key_pair.as_dict(private=False)]}

    @pytest.fixture
    def validator(self, mock_oidc_provider: Mock) -> TokenValidator:
        # Strict issuer validation
        return TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com/",
        )

    def create_token(
        self,
        key: Any,
        claims: Dict[str, Any],
        headers: Dict[str, Any] | None = None,
    ) -> str:
        if headers is None:
            headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
        return jwt.encode(headers, claims, key).decode("utf-8")  # type: ignore[no-any-return]

    @pytest.mark.asyncio
    async def test_malformed_token_structure(self, validator: TokenValidator) -> None:
        """Test that a completely malformed token string raises CoreasonIdentityError."""
        # Not a JWT (no dots)
        with pytest.raises(CoreasonIdentityError, match="Token validation failed"):
            await validator.validate_token("invalid-token-string")

        # Missing signature part (2 parts only)
        with pytest.raises(CoreasonIdentityError, match="Token validation failed"):
            await validator.validate_token("header.payload")

    @pytest.mark.asyncio
    async def test_invalid_base64(self, validator: TokenValidator) -> None:
        """Test token with invalid base64 characters."""
        with pytest.raises(CoreasonIdentityError, match="Token validation failed"):
            await validator.validate_token("header.payload.signature!")

    @pytest.mark.asyncio
    async def test_issuer_mismatch(
        self,
        validator: TokenValidator,
        mock_oidc_provider: Mock,
        key_pair: Any,
        jwks: Dict[str, Any],
    ) -> None:
        """Test that token from wrong issuer is rejected."""
        mock_oidc_provider.get_jwks.return_value = jwks

        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://evil.com/",  # Mismatch
            "exp": 9999999999,
        }
        token = self.create_token(key_pair, claims)

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_issuer_missing_in_token(
        self,
        validator: TokenValidator,
        mock_oidc_provider: Mock,
        key_pair: Any,
        jwks: Dict[str, Any],
    ) -> None:
        """Test that token missing 'iss' claim is rejected if issuer check is enabled."""
        mock_oidc_provider.get_jwks.return_value = jwks

        claims = {
            "sub": "user123",
            "aud": "my-audience",
            # "iss" missing
            "exp": 9999999999,
        }
        token = self.create_token(key_pair, claims)

        with pytest.raises(CoreasonIdentityError, match="Missing claim"):
            await validator.validate_token(token)
