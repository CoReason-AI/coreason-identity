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

from typing import Any, Dict
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from authlib.jose import JsonWebKey, jwt
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
        headers: Dict[str, Any] | None = None,
        alg: str = "RS256",
    ) -> str:
        if headers is None:
            headers = {"alg": alg, "kid": key.as_dict()["kid"] if key else "none"}
        return jwt.encode(headers, claims, key).decode("utf-8")  # type: ignore[no-any-return]

    @pytest.mark.asyncio
    async def test_alg_none_attack(self, validator: TokenValidator) -> None:
        """
        Security Test: Verify 'alg': 'none' is rejected.
        Even if the signature is empty/valid for none, we enforce RS256.
        """
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com/",
            "exp": 9999999999,
        }
        # Create token with alg: none
        # Authlib jwt.encode might refuse 'none' if key is provided, so we pass None key
        token = jwt.encode({"alg": "none"}, claims, None).decode("utf-8")

        with pytest.raises(CoreasonIdentityError, match="Token validation failed"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_audience_as_list(
        self,
        validator: TokenValidator,
        key_pair: Any,
    ) -> None:
        """
        Verify that validation passes if the token has a list of audiences
        and one of them matches the configured audience.
        """
        claims = {
            "sub": "user123",
            "aud": ["other-audience", "my-audience"],
            "iss": "https://valid-issuer.com/",
            "exp": 9999999999,
        }
        token = self.create_token(key_pair, claims)

        # Should pass
        validated = await validator.validate_token(token)
        assert validated["sub"] == "user123"

    @pytest.mark.asyncio
    async def test_key_rotation_recovery(
        self,
        validator: TokenValidator,
        key_pair: Any,
        mock_oidc_provider: Mock,
    ) -> None:
        """
        Verify that if the first validation fails (old key), it fetches fresh keys and retries.
        """
        # 1. Setup: Provider returns OLD keys initially
        old_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        new_key = key_pair  # The one signing the token

        # Initial cached JWKS has only old_key
        # We need to simulate side effect for AsyncMock
        mock_oidc_provider.get_jwks.side_effect = [
            {"keys": [old_key.as_dict(private=False)]},  # First call (cache)
            {"keys": [new_key.as_dict(private=False)]},  # Second call (fresh)
        ]

        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com/",
            "exp": 9999999999,
        }
        # Token signed with NEW key
        token = self.create_token(new_key, claims)

        # 2. Execute
        validated = await validator.validate_token(token)

        # 3. Verify
        assert validated["sub"] == "user123"
        # Verify get_jwks was called twice: once default, once with force_refresh=True
        assert mock_oidc_provider.get_jwks.call_count == 2
        mock_oidc_provider.get_jwks.assert_called_with(force_refresh=True)


class TestIdentityMapperComplex:
    def test_mapper_groups_explicit_none(self) -> None:
        """
        Test resilience against 'groups': None in payload.
        Pydantic normalization should handle this.
        """
        mapper = IdentityMapper()
        claims = {
            "sub": "u1",
            "email": "u@e.com",
            "groups": None,  # Explicit None
        }
        context = mapper.map_claims(claims)
        assert context.claims["permissions"] == []
        assert "project_context" not in context.claims

    def test_mapper_mixed_source_precedence(self) -> None:
        """
        Test complex precedence:
        - project_id_claim (Highest)
        - groups project: match
        """
        mapper = IdentityMapper()
        claims = {
            "sub": "u1",
            "email": "u@e.com",
            "https://coreason.com/project_id": "EXPLICIT_ID",
            "groups": ["project:GROUP_ID"],
        }
        context = mapper.map_claims(claims)
        # Explicit claim wins
        assert context.claims["project_context"] == "EXPLICIT_ID"

    def test_mapper_admin_group_case_insensitive(self) -> None:
        """Test 'AdMiN' does NOT map to permissions=['*'] anymore."""
        mapper = IdentityMapper()
        claims = {
            "sub": "u1",
            "email": "u@e.com",
            "groups": ["AdMiN"],
        }
        context = mapper.map_claims(claims)
        assert context.claims["permissions"] == []


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
        client = DeviceFlowClient("client-id", "https://idp.com", client=mock_client)
        # Setup endpoints
        client._endpoints = {
            "device_authorization_endpoint": "https://idp.com/device",
            "token_endpoint": "https://idp.com/token",
        }

        # Mock responses:
        # 1. slow_down
        # 2. authorization_pending
        # 3. Success
        mock_client.post.side_effect = [
            Mock(status_code=400, json=lambda: {"error": "slow_down"}),
            Mock(status_code=400, json=lambda: {"error": "authorization_pending"}),
            Mock(
                status_code=200,
                json=lambda: {
                    "access_token": "at",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            ),
        ]

        flow_response = DeviceFlowResponse(
            device_code="dc",
            user_code="uc",
            verification_uri="uri",
            expires_in=300,
            interval=5,
        )

        # Execute
        with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
            token = await client.poll_token(flow_response)

            # Verify
            assert isinstance(token, TokenResponse)
            assert token.access_token == "at"

            # Check sleep calls
            # Interval starts at 5.
            # 1. slow_down -> interval becomes 10. sleep(10) (Wait, code logic: interval += 5, then sleep(interval))
            #    Wait, in previous sync code:
            #    error == "slow_down" -> interval += 5
            #    time.sleep(interval)
            #    So if interval=5, it becomes 10, then sleeps 10.

            # 2. authorization_pending -> interval remains 10. time.sleep(10)

            # 3. Success -> return.

            assert mock_sleep.call_count == 2
            args_list = mock_sleep.call_args_list
            # First sleep: after slow_down. interval was 5, became 10.
            assert args_list[0][0][0] == 10
            # Second sleep: after auth_pending. interval is 10.
            assert args_list[1][0][0] == 10
