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
Super edge cases for coreason-identity.
Testing missing claims, empty strings, and malformed responses.
"""

from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from authlib.jose import JsonWebKey

# Helper for httpx mocks
from httpx import Request, Response

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InvalidTokenError,
)
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.models import DeviceFlowResponse
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


def create_response(status_code: int, json_data: Any | None = None) -> Response:
    request = Request("GET", "https://example.com")
    return Response(status_code, json=json_data, request=request)


class TestIdentityMapperSuperEdgeCases:
    def test_missing_sub_claim(self) -> None:
        """
        Verify InvalidTokenError when 'sub' claim is completely missing.
        """
        mapper = IdentityMapper()
        claims = {
            "email": "user@example.com",
            # sub is missing
        }
        with pytest.raises(InvalidTokenError, match="UserContext validation failed"):
            mapper.map_claims(claims)

    def test_missing_email_claim(self) -> None:
        """
        Verify InvalidTokenError when 'email' claim is completely missing.
        """
        mapper = IdentityMapper()
        claims = {
            "sub": "user123",
            # email is missing
        }
        with pytest.raises(InvalidTokenError, match="UserContext validation failed"):
            mapper.map_claims(claims)

    def test_empty_string_sub(self) -> None:
        """
        Verify behavior when 'sub' is an empty string.
        Pydantic v2 might allow empty string unless constrained, but our UserContext expects a string.
        Ideally we should check if empty sub is valid or not. Pydantic default allows it.
        """
        mapper = IdentityMapper()
        claims = {
            "sub": "",
            "email": "user@example.com",
        }
        # If valid, it returns a context with empty sub.
        context = mapper.map_claims(claims)
        assert context.user_id == ""

    def test_project_id_empty_string(self) -> None:
        """
        Verify project_id empty string from claim.
        """
        mapper = IdentityMapper()
        claims = {
            "sub": "u1",
            "email": "u@e.com",
            "https://coreason.com/project_id": "",  # Empty string
        }
        context = mapper.map_claims(claims)
        # Empty string should be passed through if it exists
        assert context.claims["project_context"] == ""


class TestDeviceFlowSuperEdgeCases:
    @pytest.fixture
    def mock_client(self) -> AsyncMock:
        return AsyncMock(spec=httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_poll_token_missing_access_token_field(self, mock_client: AsyncMock) -> None:
        """
        Verify behavior when IdP returns 200 OK but the JSON is missing 'access_token'.
        This should fail Pydantic validation of TokenResponse.
        """
        client = DeviceFlowClient("cid", "https://idp.com", client=mock_client)

        # Discovery
        mock_client.get.return_value = create_response(
            200, {
                "device_authorization_endpoint": "https://idp.com/device",
                "token_endpoint": "https://idp.com/token",
                "issuer": "https://idp",
                "jwks_uri": "https://idp/jwks",
            }
        )

        # Polling response: 200 OK but missing access_token
        # e.g. {"token_type": "Bearer"}
        mock_client.post.return_value = create_response(200, {"token_type": "Bearer", "expires_in": 3600})

        flow_resp = DeviceFlowResponse(
            device_code="dc", user_code="uc", verification_uri="uri", expires_in=10, interval=1
        )

        with (
            pytest.raises(CoreasonIdentityError, match="Received invalid token response structure"),
            patch("anyio.sleep", new_callable=AsyncMock),
        ):
            await client.poll_token(flow_resp)


class TestTokenValidatorSuperEdgeCases:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        return Mock(spec=OIDCProvider)

    @pytest.fixture
    def key_pair(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @pytest.fixture
    def jwks(self, key_pair: Any) -> dict[str, Any]:
        return {"keys": [key_pair.as_dict(private=False)]}

    @pytest.fixture
    def validator(self, mock_oidc_provider: Mock, jwks: dict[str, Any]) -> TokenValidator:
        mock_oidc_provider.get_jwks = AsyncMock(return_value=jwks)
        return TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com/",
        )

    @pytest.mark.asyncio
    async def test_malformed_json_payload_after_signature_check(self, validator: TokenValidator) -> None:
        """
        Simulate a scenario where JWT signature is valid (hypothetically) but payload is not valid JSON.
        In reality, JWT signature covers the payload, so you can't have valid signature on invalid payload
        unless the signer signed garbage.
        Authlib decode() handles base64 decoding and JSON parsing.
        If JSON parsing fails, it usually raises generic decode error.
        We can mock the jwt.decode to raise ValueError to simulate this internal failure.
        """
        with (
            patch.object(validator.jwt, "decode", side_effect=ValueError("Invalid payload JSON")),
            pytest.raises(CoreasonIdentityError, match="Invalid signature or key not found"),
        ):
            # Wait, validator catches ValueError and raises SignatureVerificationError
            # with "Invalid signature or key not found: ..."
            # Let's verify exact mapping.
            await validator.validate_token("some.token.here")
