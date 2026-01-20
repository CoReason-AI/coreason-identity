# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

"""
Final edge case tests for coreason-identity.
"""

import time
from typing import Any, Dict
from unittest.mock import AsyncMock, Mock, patch

import pytest
from authlib.jose import JsonWebKey, jwt
from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.exceptions import (
    InvalidAudienceError,
    InvalidTokenError,
)
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.manager import IdentityManager
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestIdentityManagerEdgeCases:
    @pytest.fixture
    def config(self) -> CoreasonIdentityConfig:
        return CoreasonIdentityConfig(
            domain="test.auth0.com",
            audience="my-audience",
            client_id="cid",
        )

    def test_validate_token_empty_bearer_string(self, config: CoreasonIdentityConfig) -> None:
        """Test validation when header is just 'Bearer ' with no token."""
        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
        ):
            manager = IdentityManager(config)

            # Mock validator to raise error on empty string (simulating underlying lib)
            # Access underlying async validator via _async
            # But facade validate_token calls anyio.run(_async.validate_token)

            # We can mock the validator in _async
            manager._async.validator.validate_token = AsyncMock(side_effect=InvalidTokenError("Empty token"))  # type: ignore[method-assign]

            with pytest.raises(InvalidTokenError):
                manager.validate_token("Bearer ")

            # Ensure validator was called with empty string
            manager._async.validator.validate_token.assert_called_with("")


class TestTokenValidatorTimeClaims:
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
    def validator(self, mock_oidc_provider: Mock, jwks: Dict[str, Any]) -> TokenValidator:
        mock_oidc_provider.get_jwks.return_value = jwks
        return TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com/",
        )

    def create_token(
        self,
        key: Any,
        claims: Dict[str, Any],
    ) -> str:
        headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
        return jwt.encode(headers, claims, key).decode("utf-8")  # type: ignore[no-any-return]

    @pytest.mark.asyncio
    async def test_iat_in_future(self, validator: TokenValidator, key_pair: Any) -> None:
        """
        Test token issued in the future.
        Authlib validates 'iat' by default if present and rejects tokens issued in the future.
        """
        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com/",
            "exp": now + 3600,
            "iat": now + 3600,  # Issued 1 hour in future
        }
        token = self.create_token(key_pair, claims)

        with pytest.raises(InvalidTokenError, match="issued in the future"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_nbf_in_future(self, validator: TokenValidator, key_pair: Any) -> None:
        """Test token with nbf (Not Before) in the future."""
        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com/",
            "exp": now + 3600,
            "nbf": now + 3600,  # Not valid yet
        }
        token = self.create_token(key_pair, claims)

        # Authlib validates 'nbf' by default if present.
        with pytest.raises(InvalidTokenError, match="not valid yet"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_empty_audience_list(self, validator: TokenValidator, key_pair: Any) -> None:
        """Test token with empty audience list."""
        claims = {
            "sub": "user123",
            "aud": [],  # Empty list
            "iss": "https://valid-issuer.com/",
            "exp": 9999999999,
        }
        token = self.create_token(key_pair, claims)

        with pytest.raises(InvalidAudienceError):
            await validator.validate_token(token)


class TestIdentityMapperUnexpectedTypes:
    def test_groups_as_boolean(self) -> None:
        """Test 'groups' claim as a boolean value."""
        mapper = IdentityMapper()
        claims = {
            "sub": "u1",
            "email": "u@e.com",
            "groups": True,  # Boolean
        }
        # Pydantic validator: True is not str, list, tuple.
        # Wait, isinstance(True, int) is True in Python.
        # But ensure_list_of_strings handles lists/tuples.
        # If it falls through, it returns [].
        # But wait, True is int? No, isinstance(v, (list, tuple)) is False for bool.
        # isinstance(v, str) is False.
        # So it returns [].

        context = mapper.map_claims(claims)
        assert context.permissions == []
        assert context.project_context is None

    def test_permissions_as_integer(self) -> None:
        """Test 'permissions' claim as an integer."""
        mapper = IdentityMapper()
        claims = {
            "sub": "u1",
            "email": "u@e.com",
            "permissions": 12345,
        }
        context = mapper.map_claims(claims)
        assert context.permissions == []
