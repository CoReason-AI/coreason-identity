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
from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import DeviceFlowResponse, TokenResponse
from httpx import Request, Response


@pytest.fixture()
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.fixture()
def client(mock_client: AsyncMock) -> DeviceFlowClient:
    return DeviceFlowClient(client_id="test-client", idp_url="https://test.auth0.com", client=mock_client)


def create_response(status_code: int, json_data: Any | None = None, content: bytes | None = None) -> Response:
    request = Request("GET", "https://example.com")
    if json_data is not None:
        return Response(status_code, json=json_data, request=request)
    return Response(status_code, content=content, request=request)


@pytest.mark.asyncio()
async def test_get_endpoints_success(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    mock_client.get.return_value = create_response(
        200,
        {
            "device_authorization_endpoint": "https://test.auth0.com/oauth/device/code",
            "token_endpoint": "https://test.auth0.com/oauth/token",
        },
    )

    endpoints = await client._get_endpoints()
    assert endpoints["device_authorization_endpoint"] == "https://test.auth0.com/oauth/device/code"
    assert endpoints["token_endpoint"] == "https://test.auth0.com/oauth/token"
    mock_client.get.assert_called_once_with("https://test.auth0.com/.well-known/openid-configuration")

    # Test Caching
    endpoints2 = await client._get_endpoints()
    assert endpoints2 is endpoints
    assert mock_client.get.call_count == 1


@pytest.mark.asyncio()
async def test_get_endpoints_fallback(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test fallback when specific keys are missing in config."""
    mock_client.get.return_value = create_response(200, {})  # Empty config

    endpoints = await client._get_endpoints()
    assert endpoints["device_authorization_endpoint"] == "https://test.auth0.com/oauth/device/code"
    assert endpoints["token_endpoint"] == "https://test.auth0.com/oauth/token"


@pytest.mark.asyncio()
async def test_get_endpoints_failure(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    mock_client.get.return_value = create_response(500, "Internal Server Error")

    with pytest.raises(CoreasonIdentityError, match="Failed to discover OIDC endpoints"):
        await client._get_endpoints()


@pytest.mark.asyncio()
async def test_initiate_flow_success(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    # Mock discovery
    mock_client.get.return_value = create_response(
        200,
        {
            "device_authorization_endpoint": "https://test.auth0.com/device",
            "token_endpoint": "https://test.auth0.com/token",
        },
    )

    # Mock initiation
    mock_client.post.return_value = create_response(
        200,
        {
            "device_code": "dc_123",
            "user_code": "uc_123",
            "verification_uri": "https://verify.com",
            "expires_in": 300,
            "interval": 5,
        },
    )

    resp = await client.initiate_flow(audience="api://test")

    assert isinstance(resp, DeviceFlowResponse)
    assert resp.device_code == "dc_123"
    assert resp.user_code == "uc_123"

    # Verify post args
    mock_client.post.assert_called_once()
    args, kwargs = mock_client.post.call_args
    assert args[0] == "https://test.auth0.com/device"
    assert kwargs["data"]["audience"] == "api://test"


@pytest.mark.asyncio()
async def test_initiate_flow_http_error(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    mock_client.get.return_value = create_response(200, {})
    mock_client.post.return_value = create_response(500, "Error")

    with pytest.raises(CoreasonIdentityError, match="Failed to initiate device flow"):
        await client.initiate_flow()


@pytest.mark.asyncio()
async def test_initiate_flow_validation_error(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    mock_client.get.return_value = create_response(200, {})
    mock_client.post.return_value = create_response(200, {})  # Missing fields

    with pytest.raises(CoreasonIdentityError, match="Invalid response from IdP"):
        await client.initiate_flow()


@pytest.mark.asyncio()
async def test_poll_token_success(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    # Discovery
    mock_client.get.return_value = create_response(
        200,
        {
            "token_endpoint": "https://test.auth0.com/token",
        },
    )

    # Polling responses: pending -> success
    mock_client.post.side_effect = [
        create_response(400, {"error": "authorization_pending"}),
        create_response(200, {"access_token": "at_123", "token_type": "Bearer", "expires_in": 3600}),
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        token_resp = await client.poll_token(device_resp)

    assert isinstance(token_resp, TokenResponse)
    assert token_resp.access_token == "at_123"
    assert mock_client.post.call_count == 2
    mock_sleep.assert_called_once_with(1)


@pytest.mark.asyncio()
async def test_poll_token_slow_down(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    mock_client.get.return_value = create_response(200, {"token_endpoint": "url"})

    # slow_down -> success
    mock_client.post.side_effect = [
        create_response(400, {"error": "slow_down"}),
        create_response(200, {"access_token": "at", "token_type": "Bearer", "expires_in": 3600}),
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        await client.poll_token(device_resp)
        mock_sleep.assert_called_once_with(6)


@pytest.mark.asyncio()
async def test_poll_token_access_denied(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    mock_client.get.return_value = create_response(200, {"token_endpoint": "url"})

    mock_client.post.return_value = create_response(400, {"error": "access_denied"})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        pytest.raises(CoreasonIdentityError, match="User denied access"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio()
async def test_poll_token_expired_token(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    mock_client.get.return_value = create_response(200, {"token_endpoint": "url"})

    mock_client.post.return_value = create_response(400, {"error": "expired_token"})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        pytest.raises(CoreasonIdentityError, match="Device code expired"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio()
async def test_poll_token_timeout(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    mock_client.get.return_value = create_response(200, {"token_endpoint": "url"})
    mock_client.post.return_value = create_response(400, {"error": "authorization_pending"})

    # Set expires_in to 1 second
    device_resp = DeviceFlowResponse(device_code="dc", user_code="uc", verification_uri="url", expires_in=1, interval=1)

    with patch("time.time") as mock_time, patch("anyio.sleep", new_callable=AsyncMock):
        mock_time.side_effect = [0, 0, 2]

        with pytest.raises(CoreasonIdentityError, match="Polling timed out"):
            await client.poll_token(device_resp)


@pytest.mark.asyncio()
async def test_poll_token_unexpected_error(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test when polling receives a 500 error."""
    mock_client.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 500 error - httpx.Response(500, json={"error": "server error"})
    # This should trigger response.raise_for_status() in the 'else' block or catch block
    mock_client.post.return_value = create_response(500, {"error": "server_error"})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Polling failed"), patch("anyio.sleep", new_callable=AsyncMock):
        await client.poll_token(device_resp)


@pytest.mark.asyncio()
async def test_poll_token_invalid_json_type(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test when polling receives a valid JSON that isn't a dict (e.g. list)."""
    mock_client.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 400 but returns a list?
    mock_client.post.return_value = create_response(400, ["error"])

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        pytest.raises(CoreasonIdentityError, match="Received invalid JSON response"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio()
async def test_poll_token_non_json_500(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test when polling receives non-JSON content with 500 error."""
    mock_client.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 500 with text
    mock_client.post.return_value = create_response(500, content=b"Server Error")

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Polling failed"), patch("anyio.sleep", new_callable=AsyncMock):
        await client.poll_token(device_resp)


@pytest.mark.asyncio()
async def test_poll_token_non_json_200(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test when polling receives non-JSON content with 200 OK (Unexpected)."""
    mock_client.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 200 with text - response.json() fails
    mock_client.post.return_value = create_response(200, content=b"Not JSON")

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        pytest.raises(CoreasonIdentityError, match="Received invalid JSON response on 200 OK"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio()
async def test_poll_token_204_empty(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test when polling receives 204 No Content (should trigger generic error)."""
    mock_client.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 204 No Content
    mock_client.post.return_value = create_response(204)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        pytest.raises(CoreasonIdentityError, match="Received invalid response"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio()
async def test_poll_token_generic_exception_retry(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test retry logic on generic exception."""
    mock_client.get.return_value = create_response(200, {"token_endpoint": "url"})

    # Fail once with network error, then succeed
    mock_client.post.side_effect = [
        Exception("Network Error"),
        create_response(200, {"access_token": "at_123", "token_type": "Bearer", "expires_in": 3600}),
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        token_resp = await client.poll_token(device_resp)

    assert isinstance(token_resp, TokenResponse)
    assert token_resp.access_token == "at_123"
    assert mock_client.post.call_count == 2
    mock_sleep.assert_called_once_with(1)
