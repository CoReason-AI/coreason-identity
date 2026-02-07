# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import Request, Response

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import DeviceFlowResponse


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.fixture
def client(mock_client: AsyncMock) -> DeviceFlowClient:
    return DeviceFlowClient(
        client_id="test-client", idp_url="https://test.auth0.com", client=mock_client, scope="openid profile email"
    )


def create_response(status_code: int, json_data: Any | None = None, content: bytes | None = None) -> Response:
    request = Request("GET", "https://example.com")
    if json_data is not None:
        return Response(status_code, json=json_data, request=request)
    return Response(status_code, content=content, request=request)


@pytest.mark.asyncio
async def test_poll_token_flaky_network(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test polling where requests fail intermittently (network error) but eventually succeed."""
    mock_client.get.return_value = create_response(
        200, {"token_endpoint": "url", "issuer": "https://idp", "jwks_uri": "https://idp/jwks"}
    )

    # Fail, Pending, Fail, Success
    mock_client.post.side_effect = [
        Exception("Network glitch 1"),
        create_response(400, {"error": "authorization_pending"}),
        Exception("Network glitch 2"),
        create_response(200, {"access_token": "at", "token_type": "B", "expires_in": 3600}),
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        token_resp = await client.poll_token(device_resp)
        # Should succeed
        assert token_resp.access_token == "at"
        # Total 4 calls
        assert mock_client.post.call_count == 4
        # Sleep called 3 times (after each non-success)
        assert mock_sleep.call_count == 3


@pytest.mark.asyncio
async def test_poll_token_compounding_slow_down(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test multiple slow_down responses increasing the interval."""
    mock_client.get.return_value = create_response(
        200, {"token_endpoint": "url", "issuer": "https://idp", "jwks_uri": "https://idp/jwks"}
    )

    # slow_down, slow_down, success
    mock_client.post.side_effect = [
        create_response(400, {"error": "slow_down"}),
        create_response(400, {"error": "slow_down"}),
        create_response(200, {"access_token": "at", "token_type": "B", "expires_in": 3600}),
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=20, interval=5
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        await client.poll_token(device_resp)

        # Initial interval: 5
        # 1st slow_down: interval -> 5+5=10. sleep(10).
        # 2nd slow_down: interval -> 10+5=15. sleep(15).
        # Success.

        assert mock_sleep.call_args_list == [
            ((10,),),
            ((15,),),
        ]


@pytest.mark.asyncio
async def test_poll_token_malformed_success(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test 200 OK but missing required fields (access_token)."""
    mock_client.get.return_value = create_response(
        200, {"token_endpoint": "url", "issuer": "https://idp", "jwks_uri": "https://idp/jwks"}
    )

    # 200 OK but missing 'access_token'
    mock_client.post.return_value = create_response(200, {"foo": "bar", "expires_in": 3600})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        pytest.raises(CoreasonIdentityError, match="Received invalid token response structure"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio
async def test_poll_token_legacy_error_in_200(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test 200 OK containing an error field (legacy behavior)."""
    mock_client.get.return_value = create_response(
        200, {"token_endpoint": "url", "issuer": "https://idp", "jwks_uri": "https://idp/jwks"}
    )

    # 200 OK with error payload
    mock_client.post.return_value = create_response(200, {"error": "access_denied", "error_description": "Legacy"})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    # Should raise ValidationError because access_token is missing, caught and re-raised as CoreasonIdentityError
    with (
        pytest.raises(CoreasonIdentityError, match="Received invalid token response structure"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio
async def test_discovery_complex_failure(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test discovery returns corrupted JSON, fallback logic."""

    # Discovery returns invalid JSON
    mock_client.get.return_value = create_response(200, content=b"{invalid_json}")

    with pytest.raises(CoreasonIdentityError, match="Invalid JSON response from OIDC discovery"):
        await client._get_endpoints()
