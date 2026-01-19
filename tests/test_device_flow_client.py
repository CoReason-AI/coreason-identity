# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import Mock, patch, AsyncMock
import pytest
import time
from coreason_identity.device_flow_client import DeviceFlowClient, DeviceFlowClientAsync
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import DeviceFlowResponse, TokenResponse
import httpx

def create_mock_response(json_data=None, status_code=200, content=None):
    mock_resp = Mock()
    mock_resp.status_code = status_code
    if json_data is not None:
        mock_resp.json.return_value = json_data
    if content is not None:
        mock_resp.content = content
    mock_resp.raise_for_status.side_effect = (
        None if status_code < 400 else httpx.HTTPStatusError("Error", request=Mock(), response=mock_resp)
    )
    return mock_resp

# --- Async Tests ---

@pytest.fixture
def async_client() -> DeviceFlowClientAsync:
    return DeviceFlowClientAsync(client_id="test", idp_url="https://test.auth0.com")

@pytest.mark.asyncio
async def test_async_initiate_flow_success(async_client: DeviceFlowClientAsync) -> None:
    mock_client = AsyncMock()
    async_client._client = mock_client

    mock_client.get.return_value = create_mock_response({
        "device_authorization_endpoint": "https://test.auth0.com/device",
        "token_endpoint": "https://test.auth0.com/token"
    })

    mock_client.post.return_value = create_mock_response({
        "device_code": "dc", "user_code": "uc", "verification_uri": "uri",
        "expires_in": 300, "interval": 5
    })

    resp = await async_client.initiate_flow()
    assert resp.device_code == "dc"

@pytest.mark.asyncio
async def test_async_initiate_flow_error(async_client: DeviceFlowClientAsync) -> None:
    mock_client = AsyncMock()
    async_client._client = mock_client
    mock_client.get.return_value = create_mock_response({"device_authorization_endpoint": "url"})
    mock_client.post.return_value = create_mock_response(status_code=500)

    with pytest.raises(CoreasonIdentityError):
        await async_client.initiate_flow()

@pytest.mark.asyncio
async def test_async_poll_token_success(async_client: DeviceFlowClientAsync) -> None:
    mock_client = AsyncMock()
    async_client._client = mock_client

    mock_client.get.return_value = create_mock_response({
        "token_endpoint": "https://test.auth0.com/token"
    })

    mock_client.post.side_effect = [
        create_mock_response(status_code=400, json_data={"error": "authorization_pending"}),
        create_mock_response(status_code=400, json_data={"error": "authorization_pending"}),
        create_mock_response(status_code=200, json_data={"access_token": "at", "token_type": "Bearer", "expires_in": 3600})
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="uri", expires_in=10, interval=1
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        token = await async_client.poll_token(device_resp)

    assert token.access_token == "at"
    assert mock_sleep.call_count == 2

@pytest.mark.asyncio
async def test_async_poll_token_slow_down(async_client: DeviceFlowClientAsync) -> None:
    mock_client = AsyncMock()
    async_client._client = mock_client
    mock_client.get.return_value = create_mock_response({"token_endpoint": "url"})

    mock_client.post.side_effect = [
        create_mock_response(status_code=400, json_data={"error": "slow_down"}),
        create_mock_response(status_code=200, json_data={"access_token": "at", "token_type": "Bearer", "expires_in": 3600})
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="uri", expires_in=10, interval=1
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        await async_client.poll_token(device_resp)

    mock_sleep.assert_called_with(6)

@pytest.mark.asyncio
async def test_async_poll_token_expired(async_client: DeviceFlowClientAsync) -> None:
    mock_client = AsyncMock()
    async_client._client = mock_client
    mock_client.get.return_value = create_mock_response({"token_endpoint": "url"})

    mock_client.post.return_value = create_mock_response(status_code=400, json_data={"error": "expired_token"})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="uri", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Device code expired"):
        with patch("anyio.sleep", new_callable=AsyncMock):
             await async_client.poll_token(device_resp)

@pytest.mark.asyncio
async def test_async_poll_token_access_denied(async_client: DeviceFlowClientAsync) -> None:
    mock_client = AsyncMock()
    async_client._client = mock_client
    mock_client.get.return_value = create_mock_response({"token_endpoint": "url"})

    mock_client.post.return_value = create_mock_response(status_code=400, json_data={"error": "access_denied"})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="uri", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="User denied access"):
        with patch("anyio.sleep", new_callable=AsyncMock):
             await async_client.poll_token(device_resp)

@pytest.mark.asyncio
async def test_async_poll_token_timeout(async_client: DeviceFlowClientAsync) -> None:
    mock_client = AsyncMock()
    async_client._client = mock_client
    mock_client.get.return_value = create_mock_response({"token_endpoint": "url"})
    mock_client.post.return_value = create_mock_response(status_code=400, json_data={"error": "authorization_pending"})

    # Use integers for Pydantic
    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="uri", expires_in=1, interval=1
    )

    # Mock time to simulate timeout
    with patch("time.time") as mock_time, patch("anyio.sleep", new_callable=AsyncMock):
        mock_time.side_effect = [0, 0, 2] # start, check, check (timeout)

        with pytest.raises(CoreasonIdentityError, match="Polling timed out"):
             await async_client.poll_token(device_resp)

# --- Sync Facade Tests ---
@pytest.fixture
def sync_client() -> DeviceFlowClient:
    return DeviceFlowClient(client_id="test", idp_url="https://test.auth0.com")

def test_sync_initiate_flow(sync_client: DeviceFlowClient) -> None:
    with patch("coreason_identity.device_flow_client.httpx.AsyncClient") as MockClientCls:
        mock_client = AsyncMock()
        MockClientCls.return_value = mock_client
        mock_client.get.return_value = create_mock_response({
            "device_authorization_endpoint": "https://test.auth0.com/device",
            "token_endpoint": "https://test.auth0.com/token"
        })
        mock_client.post.return_value = create_mock_response({
            "device_code": "dc", "user_code": "uc", "verification_uri": "uri",
            "expires_in": 300, "interval": 5
        })

        with sync_client as client:
            resp = client.initiate_flow()

        assert resp.device_code == "dc"

def test_sync_poll_token(sync_client: DeviceFlowClient) -> None:
    with patch("coreason_identity.device_flow_client.httpx.AsyncClient") as MockClientCls:
        mock_client = AsyncMock()
        MockClientCls.return_value = mock_client
        mock_client.get.return_value = create_mock_response({
             "token_endpoint": "https://test.auth0.com/token",
             "device_authorization_endpoint": "uri"
        })
        mock_client.post.return_value = create_mock_response({
             "access_token": "at", "token_type": "Bearer", "expires_in": 3600
        })

        device_resp = DeviceFlowResponse(
            device_code="dc", user_code="uc", verification_uri="uri", expires_in=10, interval=1
        )

        with sync_client as client:
             token = client.poll_token(device_resp)

        assert token.access_token == "at"

def test_sync_usage_fail(sync_client: DeviceFlowClient) -> None:
    with pytest.raises(CoreasonIdentityError, match="Context not started"):
        sync_client.initiate_flow()
