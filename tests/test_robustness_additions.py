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
Additional robustness tests for complex edge cases not explicitly covered by existing suites.
"""

from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import Request, Response

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.models import DeviceFlowResponse, CoreasonGroup


# Helper for httpx mocks
def create_response(status_code: int, json_data: Any | None = None) -> Response:
    request = Request("GET", "https://example.com")
    return Response(status_code, json=json_data, request=request)


class TestIdentityMapperRobustness:
    def test_groups_with_mixed_types(self) -> None:
        """
        Verify that 'groups' containing mixed types are handled.
        """
        mapper = IdentityMapper()
        claims = {
            "sub": "u1",
            "email": "u@e.com",
            "groups": ["admin", "project:apollo"],
        }
        context = mapper.map_claims(claims)
        # Groups should map correctly
        assert context.groups == [CoreasonGroup.ADMIN, CoreasonGroup.PROJECT_APOLLO]

        claims_mixed = {
            "sub": "u1",
            "email": "u@e.com",
            "groups": ["admin", 123, True],
        }

        # 123 and True are converted to strings "123", "True" by RawIdPClaims,
        # but UserContext rejects them as invalid enums.
        # IdentityMapper wraps exceptions in CoreasonIdentityError.
        with pytest.raises(CoreasonIdentityError, match="UserContext validation failed"):
            mapper.map_claims(claims_mixed)

class TestDeviceFlowClientRobustness:
    @pytest.fixture
    def mock_client(self) -> AsyncMock:
        return AsyncMock(spec=httpx.AsyncClient)

    @pytest.fixture
    def client(self, mock_client: AsyncMock) -> DeviceFlowClient:
        return DeviceFlowClient("client-id", "https://idp.com", client=mock_client, scope="openid profile email")

    @pytest.mark.asyncio
    async def test_initiate_flow_timeout(self, client: DeviceFlowClient, mock_client: AsyncMock) -> None:
        """
        Verify that a network timeout during initiation is caught and raised as CoreasonIdentityError.
        """
        # Discovery succeeds
        mock_client.get.return_value = create_response(
            200,
            {
                "device_authorization_endpoint": "https://idp.com/device",
                "token_endpoint": "https://idp.com/token",
                "issuer": "https://idp",
                "jwks_uri": "https://idp/jwks",
            },
        )

        # Post fails with ReadTimeout (must be httpx error)
        mock_client.post.side_effect = httpx.ReadTimeout("Timeout")

        with pytest.raises(CoreasonIdentityError, match="Failed to initiate device flow"):
            await client.initiate_flow()

    @pytest.mark.asyncio
    async def test_poll_token_expired_response_structure(
        self, client: DeviceFlowClient, mock_client: AsyncMock
    ) -> None:
        """
        Verify handling of 'expired_token' error response.
        """
        mock_client.get.return_value = create_response(
            200,
            {
                "token_endpoint": "url",
                "issuer": "https://idp",
                "jwks_uri": "https://idp/jwks",
            },
        )

        # Return expired_token error
        mock_client.post.return_value = create_response(400, {"error": "expired_token"})

        flow_resp = DeviceFlowResponse(
            device_code="dc", user_code="uc", verification_uri="uri", expires_in=10, interval=1
        )

        with (
            pytest.raises(CoreasonIdentityError, match="Device code expired"),
            patch("anyio.sleep", new_callable=AsyncMock),
        ):
            await client.poll_token(flow_resp)
