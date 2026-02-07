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
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from authlib.jose import JsonWebKey, jwt

from coreason_identity.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
)
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestValidatorSecurity:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        provider = Mock(spec=OIDCProvider)
        provider.get_jwks = AsyncMock()
        provider.get_issuer = AsyncMock(return_value="https://valid-issuer.com")
        return provider

    @pytest.fixture
    def rsa_key_pair(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @pytest.fixture
    def oct_key(self) -> Any:
        # For HS256
        return JsonWebKey.generate_key("oct", 256, is_private=True)

    @pytest.fixture
    def jwks(self, rsa_key_pair: Any) -> dict[str, Any]:
        return {"keys": [rsa_key_pair.as_dict(private=False)]}

    def create_token(
        self, key: Any, claims: dict[str, Any], headers: dict[str, Any] | None = None, alg: str = "RS256"
    ) -> str:
        if headers is None:
            headers = {"alg": alg, "kid": key.as_dict().get("kid")}
        token_bytes = jwt.encode(headers, claims, key)
        return token_bytes.decode("utf-8")

    @pytest.mark.asyncio
    async def test_algorithm_enforcement_rejects_hs256(
        self, mock_oidc_provider: Mock, oct_key: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Verify that a token signed with HS256 is rejected when only RS256 is allowed.
        This prevents Key Confusion attacks.
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        # Configure validator to only allow RS256
        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256"],
            leeway=0,
        )

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now + 3600,
        }

        # Sign with HS256
        token = self.create_token(oct_key, claims, alg="HS256")

        # Should fail because algorithm is not allowed
        # Authlib raises JoseError which TokenValidator wraps in InvalidTokenError
        with pytest.raises(InvalidTokenError):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_zero_leeway_enforcement(
        self, mock_oidc_provider: Mock, rsa_key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Verify that a token expired by 1 second is rejected with 0 leeway.
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256"],
            leeway=0,  # Zero tolerance
        )

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now - 1,  # Expired 1 second ago
        }

        token = self.create_token(rsa_key_pair, claims)

        with pytest.raises(TokenExpiredError, match="Token has expired"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_leeway_configuration_allowance(
        self, mock_oidc_provider: Mock, rsa_key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Verify that leeway allows slightly expired tokens when configured.
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256"],
            leeway=10,  # 10 seconds leeway
        )

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now - 5,  # Expired 5 seconds ago
        }

        token = self.create_token(rsa_key_pair, claims)

        # Should pass
        payload = await validator.validate_token(token)
        assert payload["sub"] == "user123"

    @pytest.mark.asyncio
    async def test_nbf_claim_enforcement_strict(
        self, mock_oidc_provider: Mock, rsa_key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Verify that 'nbf' (Not Before) claim is strictly enforced with 0 leeway.
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256"],
            leeway=0,
        )

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now + 3600,
            "nbf": now + 5,  # Valid in 5 seconds (future)
        }

        token = self.create_token(rsa_key_pair, claims)

        # Should fail as token is not yet valid
        with pytest.raises(InvalidTokenError, match=r"Token validation failed:.*not valid yet"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_nbf_claim_with_leeway(
        self, mock_oidc_provider: Mock, rsa_key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Verify that 'nbf' claim allows slight clock skew with leeway.
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256"],
            leeway=10,
        )

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now + 3600,
            "nbf": now + 5,  # Valid in 5 seconds (future)
        }

        token = self.create_token(rsa_key_pair, claims)

        # Should pass because 5s future is within 10s leeway
        payload = await validator.validate_token(token)
        assert payload["sub"] == "user123"

    @pytest.mark.asyncio
    async def test_exp_boundary_condition(
        self, mock_oidc_provider: Mock, rsa_key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Verify behavior when token expires exactly at current time.
        Authlib usually considers exp as exclusive upper bound (exp <= now is expired),
        or inclusive? RFC 7519 says: processing of the "exp" claim requires that the current
        date/time MUST be before the expiration date/time. So exp=now is expired.
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256"],
            leeway=0,
        )

        now = int(time.time())
        # To strictly guarantee expiration failure, we check 1 second in the past
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now - 1,  # Expired
        }

        token = self.create_token(rsa_key_pair, claims)

        # Should fail immediately
        with pytest.raises(TokenExpiredError):
            await validator.validate_token(token)
