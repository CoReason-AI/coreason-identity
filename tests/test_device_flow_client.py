# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import DeviceFlowResponse, TokenResponse


# Helper for stream mocking
class MockResponse:
    def __init__(self, status_code: int, json_data: Any | None = None, content: bytes | None = None):
        self.status_code = status_code
        self._json = json_data
        self._content = content
        self.headers = {}

        body = b""
        if json_data is not None:
            body = json.dumps(json_data).encode("utf-8")
        elif content is not None:
            body = content

        self.headers["Content-Length"] = str(len(body))
        self._body = body

    async def aiter_bytes(self) -> AsyncGenerator[bytes, None]:
        yield self._body

    def json(self) -> Any:
        if self._json is not None:
            return self._json
        if self._content:
            return json.loads(self._content)
        raise ValueError("No content")

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("Error", request=None, response=self)  # type: ignore


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.fixture
def client(mock_client: AsyncMock) -> DeviceFlowClient:
    return DeviceFlowClient(
        client_id="test-client",
        idp_url="https://test.auth0.com",
        client=mock_client,
        min_poll_interval=1.0,
        scope="openid profile email",
    )


OIDC_CONFIG_BASE = {
    "issuer": "https://test.auth0.com",
    "jwks_uri": "https://test.auth0.com/.well-known/jwks.json",
}


def setup_stream_mock(mock_client: AsyncMock, responses: list[MockResponse] | MockResponse) -> None:
    if not isinstance(responses, list):
        responses = [responses]

    response_iter = iter(responses)

    @asynccontextmanager
    async def mock_stream(method: str, url: str, **kwargs: Any) -> AsyncGenerator[MockResponse, None]:
        _ = method
        _ = url
        _ = kwargs
        try:
            yield next(response_iter)
        except StopIteration:
            # Fallback for when we run out of specific responses (shouldn't happen in well-defined tests)
            yield MockResponse(500, content=b"Unexpected End of Mock Stream")

    mock_client.stream.side_effect = mock_stream


@pytest.mark.asyncio
async def test_get_endpoints_success(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    resp = MockResponse(
        200,
        {
            **OIDC_CONFIG_BASE,
            "device_authorization_endpoint": "https://test.auth0.com/oauth/device/code",
            "token_endpoint": "https://test.auth0.com/oauth/token",
        },
    )
    setup_stream_mock(mock_client, resp)

    endpoints = await client._get_endpoints()
    assert endpoints["device_authorization_endpoint"] == "https://test.auth0.com/oauth/device/code"
    assert endpoints["token_endpoint"] == "https://test.auth0.com/oauth/token"

    # Verify stream called with correct URL
    args, _ = mock_client.stream.call_args
    assert args[1] == "https://test.auth0.com/.well-known/openid-configuration"

    # Test Caching
    endpoints2 = await client._get_endpoints()
    assert endpoints2 is endpoints
    assert mock_client.stream.call_count == 1


@pytest.mark.asyncio
async def test_get_endpoints_fallback(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test fallback when specific keys are missing in config."""
    resp = MockResponse(200, OIDC_CONFIG_BASE)
    setup_stream_mock(mock_client, resp)

    endpoints = await client._get_endpoints()
    assert endpoints["device_authorization_endpoint"] == "https://test.auth0.com/oauth/device/code"
    assert endpoints["token_endpoint"] == "https://test.auth0.com/oauth/token"


@pytest.mark.asyncio
async def test_get_endpoints_failure(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    resp = MockResponse(500, content=b"Internal Server Error")
    setup_stream_mock(mock_client, resp)

    with pytest.raises(CoreasonIdentityError, match="Failed to discover OIDC endpoints"):
        await client._get_endpoints()


@pytest.mark.asyncio
async def test_initiate_flow_success(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    # 1. Discovery, 2. Initiation
    responses = [
        MockResponse(
            200,
            {
                **OIDC_CONFIG_BASE,
                "device_authorization_endpoint": "https://test.auth0.com/device",
                "token_endpoint": "https://test.auth0.com/token",
            },
        ),
        MockResponse(
            200,
            {
                "device_code": "dc_123",
                "user_code": "uc_123",
                "verification_uri": "https://verify.com",
                "expires_in": 300,
                "interval": 5,
            },
        ),
    ]
    setup_stream_mock(mock_client, responses)

    resp = await client.initiate_flow(audience="api://test")

    assert isinstance(resp, DeviceFlowResponse)
    assert resp.device_code == "dc_123"
    assert resp.user_code == "uc_123"

    # Verify calls
    assert mock_client.stream.call_count == 2
    # Check initiation call (last call)
    args, kwargs = mock_client.stream.call_args
    assert args[0] == "POST"
    assert args[1] == "https://test.auth0.com/device"
    assert kwargs["data"]["audience"] == "api://test"


@pytest.mark.asyncio
async def test_initiate_flow_http_error(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    responses = [
        MockResponse(200, OIDC_CONFIG_BASE),
        MockResponse(500, content=b"Error"),
    ]
    setup_stream_mock(mock_client, responses)

    with pytest.raises(CoreasonIdentityError, match="Failed to initiate device flow"):
        await client.initiate_flow()


@pytest.mark.asyncio
async def test_initiate_flow_validation_error(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    responses = [
        MockResponse(200, OIDC_CONFIG_BASE),
        MockResponse(200, {}),  # Missing fields
    ]
    setup_stream_mock(mock_client, responses)

    with pytest.raises(CoreasonIdentityError, match="Invalid response from IdP"):
        await client.initiate_flow()


@pytest.mark.asyncio
async def test_poll_token_success(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    responses = [
        # Discovery
        MockResponse(
            200,
            {
                **OIDC_CONFIG_BASE,
                "token_endpoint": "https://test.auth0.com/token",
            },
        ),
        # Polling: pending -> success
        MockResponse(400, {"error": "authorization_pending"}),
        MockResponse(200, {"access_token": "at_123", "token_type": "Bearer", "expires_in": 3600}),
    ]
    setup_stream_mock(mock_client, responses)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        token_resp = await client.poll_token(device_resp)

    assert isinstance(token_resp, TokenResponse)
    assert token_resp.access_token == "at_123"
    assert mock_client.stream.call_count == 3
    mock_sleep.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_poll_token_slow_down(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    responses = [
        MockResponse(200, {**OIDC_CONFIG_BASE, "token_endpoint": "url"}),
        MockResponse(400, {"error": "slow_down"}),
        MockResponse(200, {"access_token": "at", "token_type": "Bearer", "expires_in": 3600}),
    ]
    setup_stream_mock(mock_client, responses)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        await client.poll_token(device_resp)
        mock_sleep.assert_called_once_with(6)


@pytest.mark.asyncio
async def test_poll_token_access_denied(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    responses = [
        MockResponse(200, {**OIDC_CONFIG_BASE, "token_endpoint": "url"}),
        MockResponse(400, {"error": "access_denied"}),
    ]
    setup_stream_mock(mock_client, responses)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        pytest.raises(CoreasonIdentityError, match="User denied access"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio
async def test_poll_token_expired_token(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    responses = [
        MockResponse(200, {**OIDC_CONFIG_BASE, "token_endpoint": "url"}),
        MockResponse(400, {"error": "expired_token"}),
    ]
    setup_stream_mock(mock_client, responses)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        pytest.raises(CoreasonIdentityError, match="Device code expired"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio
async def test_poll_token_timeout(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    # Setup infinite pending responses
    class InfinitePending:
        def __init__(self) -> None:
            self.resp = MockResponse(400, {"error": "authorization_pending"})

        def __iter__(self) -> "InfinitePending":
            return self

        def __next__(self) -> MockResponse:
            return self.resp

    # Need discovery first
    responses = [MockResponse(200, {**OIDC_CONFIG_BASE, "token_endpoint": "url"})]

    # We can't strictly use list for infinite, but we can make the generator handle it
    # Modified setup_stream_mock handles iterables.

    # For timeout test, we rely on time.time mocking mostly, so a few pending responses are enough
    responses.extend([MockResponse(400, {"error": "authorization_pending"})] * 10)

    setup_stream_mock(mock_client, responses)

    # Set expires_in to 1 second
    device_resp = DeviceFlowResponse(device_code="dc", user_code="uc", verification_uri="url", expires_in=1, interval=1)

    with patch("time.time") as mock_time, patch("anyio.sleep", new_callable=AsyncMock):
        mock_time.side_effect = [0, 0, 2, 2, 2, 2, 2]  # Force timeout check

        with pytest.raises(CoreasonIdentityError, match="Polling timed out"):
            await client.poll_token(device_resp)


@pytest.mark.asyncio
async def test_poll_token_unexpected_error(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test when polling receives a 500 error."""
    responses = [
        MockResponse(200, {**OIDC_CONFIG_BASE, "token_endpoint": "url"}),
        MockResponse(500, {"error": "server_error"}),
    ]
    setup_stream_mock(mock_client, responses)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Polling failed"), patch("anyio.sleep", new_callable=AsyncMock):
        await client.poll_token(device_resp)


@pytest.mark.asyncio
async def test_poll_token_invalid_json_type(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test when polling receives a valid JSON that isn't a dict (e.g. list)."""
    responses = [
        MockResponse(200, {**OIDC_CONFIG_BASE, "token_endpoint": "url"}),
        MockResponse(400, ["error"]),  # Not a dict
    ]
    setup_stream_mock(mock_client, responses)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        # It triggers raise_for_status -> HTTPStatusError -> Polling failed
        pytest.raises(CoreasonIdentityError, match="Polling failed"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio
async def test_poll_token_non_json_500(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test when polling receives non-JSON content with 500 error."""
    responses = [
        MockResponse(200, {**OIDC_CONFIG_BASE, "token_endpoint": "url"}),
        MockResponse(500, content=b"Server Error"),
    ]
    setup_stream_mock(mock_client, responses)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Polling failed"), patch("anyio.sleep", new_callable=AsyncMock):
        await client.poll_token(device_resp)


@pytest.mark.asyncio
async def test_poll_token_non_json_200(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test when polling receives non-JSON content with 200 OK (Unexpected)."""
    responses = [
        MockResponse(200, {**OIDC_CONFIG_BASE, "token_endpoint": "url"}),
        MockResponse(200, content=b"Not JSON"),
    ]
    setup_stream_mock(mock_client, responses)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        pytest.raises(CoreasonIdentityError, match="Invalid JSON response"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio
async def test_poll_token_204_empty(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test when polling receives 204 No Content (should trigger generic error)."""
    responses = [
        MockResponse(200, {**OIDC_CONFIG_BASE, "token_endpoint": "url"}),
        MockResponse(204),
    ]
    setup_stream_mock(mock_client, responses)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with (
        # raise_for_status won't raise for 204, but json load fails?
        # Wait, if 204, content is empty. json.loads(b"") raises JSONDecodeError.
        # So it raises Invalid JSON response.
        pytest.raises(CoreasonIdentityError, match="Invalid JSON response"),
        patch("anyio.sleep", new_callable=AsyncMock),
    ):
        await client.poll_token(device_resp)


@pytest.mark.asyncio
async def test_poll_token_generic_exception_retry(client: DeviceFlowClient, mock_client: AsyncMock) -> None:
    """Test retry logic on generic exception."""
    # This one is tricky because mock_stream is a context manager.
    # We need side_effect to raise Exception for one call, then yield response.

    # Custom side effect for this test
    responses = iter(
        [
            MockResponse(200, {**OIDC_CONFIG_BASE, "token_endpoint": "url"}),
            MockResponse(200, {"access_token": "at_123", "token_type": "Bearer", "expires_in": 3600}),
        ]
    )

    call_count = 0

    @asynccontextmanager
    async def mock_stream_retry(method: str, url: str, **kwargs: Any) -> AsyncGenerator[MockResponse, None]:
        _ = method
        _ = url
        _ = kwargs
        nonlocal call_count
        call_count += 1
        if call_count == 2:  # First poll attempt
            raise Exception("Network Error")
        yield next(responses)

    mock_client.stream.side_effect = mock_stream_retry

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        token_resp = await client.poll_token(device_resp)

    assert isinstance(token_resp, TokenResponse)
    assert token_resp.access_token == "at_123"
    assert mock_client.stream.call_count == 3  # Discovery, Fail, Success
    mock_sleep.assert_called_once_with(1)
