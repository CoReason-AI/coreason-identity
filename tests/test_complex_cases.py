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
Complex and edge case tests for coreason-identity.
"""

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from authlib.jose import JsonWebKey, jwt
from pydantic import SecretStr

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import (
    CoreasonIdentityError,
)
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.models import DeviceFlowResponse, TokenResponse
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestTokenValidatorComplex:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        provider = Mock(spec=OIDCProvider)
        provider.get_jwks = AsyncMock()
        return provider

    @pytest.fixture
    def key_pair(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @pytest.fixture
    def jwks(self, key_pair: Any) -> dict[str, Any]:
        return {"keys": [key_pair.as_dict(private=False)]}

    @pytest.fixture
    def validator(self, mock_oidc_provider: Mock, jwks: dict[str, Any]) -> TokenValidator:
        mock_oidc_provider.get_jwks.return_value = jwks
        return TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com/",
            pii_salt=SecretStr("test-salt"),
            allowed_algorithms=["RS256"],
        )

    def create_token(
        self,
        key: Any,
        claims: dict[str, Any],
        headers: dict[str, Any] | None = None,
        alg: str = "RS256",
    ) -> str:
        if headers is None:
            headers = {"alg": alg, "kid": key.as_dict()["kid"] if key else "none"}
        return jwt.encode(headers, claims, key).decode("utf-8")

    @pytest.mark.asyncio
    async def test_alg_none_attack(self, validator: TokenValidator) -> None:
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com/",
            "exp": 9999999999,
        }
        import base64

        def base64url_encode(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

        header = {"alg": "none", "typ": "JWT"}
        payload = json.dumps(claims).encode("utf-8")
        token = f"{base64url_encode(json.dumps(header).encode('utf-8'))}.{base64url_encode(payload)}."

        with pytest.raises(CoreasonIdentityError, match="Token validation failed"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_audience_as_list(
        self,
        validator: TokenValidator,
        key_pair: Any,
    ) -> None:
        claims = {
            "sub": "user123",
            "aud": ["other-audience", "my-audience"],
            "iss": "https://valid-issuer.com/",
            "exp": 9999999999,
        }
        token = self.create_token(key_pair, claims)
        validated = await validator.validate_token(token)
        assert validated["sub"] == "user123"

    @pytest.mark.asyncio
    async def test_key_rotation_recovery(
        self,
        validator: TokenValidator,
        key_pair: Any,
        mock_oidc_provider: Mock,
    ) -> None:
        old_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        new_key = key_pair
        mock_oidc_provider.get_jwks.side_effect = [
            {"keys": [old_key.as_dict(private=False)]},
            {"keys": [new_key.as_dict(private=False)]},
        ]
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com/",
            "exp": 9999999999,
        }
        token = self.create_token(new_key, claims)
        validated = await validator.validate_token(token)
        assert validated["sub"] == "user123"
        assert mock_oidc_provider.get_jwks.call_count == 2
        mock_oidc_provider.get_jwks.assert_called_with(force_refresh=True)


class TestIdentityMapperComplex:
    def test_mapper_groups_explicit_none(self) -> None:
        mapper = IdentityMapper()
        claims = {
            "sub": "u1",
            "email": "u@e.com",
            "groups": None,
        }
        context = mapper.map_claims(claims)
        assert context.groups == []

    def test_mapper_admin_group_case_insensitive(self) -> None:
        mapper = IdentityMapper()
        claims = {
            "sub": "u1",
            "email": "u@e.com",
            "groups": ["AdMiN"],
        }
        with pytest.raises(CoreasonIdentityError, match="UserContext validation failed"):
            mapper.map_claims(claims)


class TestDeviceFlowClientComplex:
    @pytest.fixture
    def mock_client(self) -> AsyncMock:
        return AsyncMock(spec=httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_poll_token_slow_down_logic(
        self,
        mock_client: AsyncMock,
    ) -> None:
        """
        Verify that the client increases polling interval when receiving 'slow_down'.
        """
        client = DeviceFlowClient("client-id", "https://idp.com", client=mock_client, scope="openid profile email")
        client._endpoints = {
            "device_authorization_endpoint": "https://idp.com/device",
            "token_endpoint": "https://idp.com/token",
        }

        # Helper to simulate a response yielded by client.stream
        class FakeStreamResponse:
            def __init__(self, status_code: int, json_data: dict[str, Any]):
                self.status_code = status_code
                self._json = json_data
                self.headers = {"Content-Length": str(len(json.dumps(json_data)))}

            async def aiter_bytes(self) -> AsyncGenerator[bytes, None]:
                yield json.dumps(self._json).encode("utf-8")

            def raise_for_status(self) -> None:
                if self.status_code >= 400:
                    raise httpx.HTTPStatusError("Error", request=None, response=self)  # type: ignore

        # The sequence of responses:
        responses = [
            FakeStreamResponse(400, {"error": "slow_down"}),
            FakeStreamResponse(400, {"error": "authorization_pending"}),
            FakeStreamResponse(
                200,
                {
                    "access_token": "at",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            ),
        ]

        @asynccontextmanager
        async def mock_stream(*args: Any, **kwargs: Any) -> AsyncGenerator[FakeStreamResponse, None]:
            # Consume unused args to satisfy linter
            _ = args
            _ = kwargs
            yield responses.pop(0)

        # Mock the stream method to return our context manager
        mock_client.stream.side_effect = mock_stream

        flow_response = DeviceFlowResponse(
            device_code="dc",
            user_code="uc",
            verification_uri="uri",
            expires_in=300,
            interval=5,
        )

        with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
            token = await client.poll_token(flow_response)

            assert isinstance(token, TokenResponse)
            assert token.access_token == "at"

            assert mock_sleep.call_count == 2
            args_list = mock_sleep.call_args_list
            # 5 + 5 = 10
            assert args_list[0][0][0] == 10
            # remains 10
            assert args_list[1][0][0] == 10
