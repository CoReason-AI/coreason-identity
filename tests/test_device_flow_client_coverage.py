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
Tests for improving coverage of DeviceFlowClient.
"""

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError, OversizedResponseError
from coreason_identity.models import DeviceFlowResponse


# Helper for stream mocking (Copied from test_device_flow_client.py)
class MockResponse:
    def __init__(self, status_code: int, json_data: Any | None = None, content: bytes | None = None) -> None:
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


def setup_stream_mock(mock_client: AsyncMock, responses: list[MockResponse] | MockResponse) -> None:
    if not isinstance(responses, list):
        responses = [responses]

    response_iter = iter(responses)

    @asynccontextmanager
    async def mock_stream(_method: str, _url: str, **_kwargs: Any) -> AsyncGenerator[MockResponse, None]:
        try:
            yield next(response_iter)
        except StopIteration:
            yield MockResponse(500, content=b"Unexpected End of Mock Stream")

    mock_client.stream.side_effect = mock_stream


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


class TestDeviceFlowClientCoverage:
    @pytest.mark.asyncio
    async def test_get_endpoints_caching(self, mock_client: AsyncMock) -> None:
        """Test lines 90-91: caching of endpoints."""
        client = DeviceFlowClient("cid", "https://idp.com", client=mock_client, scope="scope")

        # Manually inject endpoints to bypass discovery logic
        cached_endpoints = {"device_authorization_endpoint": "d", "token_endpoint": "t"}
        client._endpoints = cached_endpoints

        endpoints = await client._get_endpoints()
        assert endpoints is cached_endpoints
        # Ensure no network calls were made
        assert mock_client.stream.call_count == 0

    @pytest.mark.asyncio
    async def test_poll_token_oversized_response_header(self, mock_client: AsyncMock) -> None:
        """Test lines 190-192: Oversized content length header."""
        client = DeviceFlowClient("cid", "https://idp.com", client=mock_client, scope="scope")
        client._endpoints = {"device_authorization_endpoint": "d", "token_endpoint": "t"}

        # Mock response with large content-length header
        mock_response = MockResponse(200, {})
        mock_response.headers["Content-Length"] = str(1_000_001)

        setup_stream_mock(mock_client, mock_response)

        device_resp = DeviceFlowResponse(
            device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
        )

        # Should raise OversizedResponseError which is caught and logged as "Polling attempt failed"
        # Since loop continues, we need to break it or mock time.
        # But wait, it catches Exception and logs warning, then continues polling.
        # Eventually it times out.

        # To verify the specific path, we can check that it didn't return success.
        # Or mock time to force timeout quickly.

        with patch("anyio.sleep", new_callable=AsyncMock), \
             patch("time.time", side_effect=[0, 100, 200]): # Start, first check, timeout

            # It will fail polling once then timeout
            with pytest.raises(CoreasonIdentityError, match="Polling timed out"):
                await client.poll_token(device_resp)

    @pytest.mark.asyncio
    async def test_poll_token_oversized_response_body(self, mock_client: AsyncMock) -> None:
        """Test lines 198: Oversized body during streaming."""
        client = DeviceFlowClient("cid", "https://idp.com", client=mock_client, scope="scope")
        client._endpoints = {"device_authorization_endpoint": "d", "token_endpoint": "t"}

        # Mock response with valid header but large body
        mock_response = MockResponse(200, content=b"a" * 1_000_001)
        # Reset content length header to be valid so it passes first check
        mock_response.headers["Content-Length"] = "100"

        setup_stream_mock(mock_client, mock_response)

        device_resp = DeviceFlowResponse(
            device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
        )

        with patch("anyio.sleep", new_callable=AsyncMock), \
             patch("time.time", side_effect=[0, 100, 200]):

            with pytest.raises(CoreasonIdentityError, match="Polling timed out"):
                await client.poll_token(device_resp)

    @pytest.mark.asyncio
    async def test_poll_token_timeout_safety_limit(self, mock_client: AsyncMock) -> None:
        """Test lines 256: Polling safety limit reached."""
        client = DeviceFlowClient("cid", "https://idp.com", client=mock_client, scope="scope", max_poll_duration=1.0)
        client._endpoints = {"device_authorization_endpoint": "d", "token_endpoint": "t"}

        # Just return pending so it loops
        setup_stream_mock(mock_client, MockResponse(400, {"error": "authorization_pending"}))

        device_resp = DeviceFlowResponse(
            device_code="dc", user_code="uc", verification_uri="url", expires_in=100, interval=1
        )

        # Mock time to exceed safety limit immediately
        with patch("anyio.sleep", new_callable=AsyncMock), \
             patch("time.time", side_effect=[0, 2.0, 3.0]): # Start, after sleep (safety check)

            with pytest.raises(CoreasonIdentityError, match="Polling timed out \(safety limit reached\)"):
                await client.poll_token(device_resp)

    @pytest.mark.asyncio
    async def test_poll_token_timeout_expires_in(self, mock_client: AsyncMock) -> None:
        """Test lines 249: Polling timed out (expires_in)."""
        client = DeviceFlowClient("cid", "https://idp.com", client=mock_client, scope="scope")
        client._endpoints = {"device_authorization_endpoint": "d", "token_endpoint": "t"}

        setup_stream_mock(mock_client, MockResponse(400, {"error": "authorization_pending"}))

        # expires_in is small
        device_resp = DeviceFlowResponse(
            device_code="dc", user_code="uc", verification_uri="url", expires_in=1, interval=1
        )

        with patch("anyio.sleep", new_callable=AsyncMock), \
             patch("time.time", side_effect=[0, 2.0, 3.0]): # Start, after sleep (loop check)

            # Loop condition: time.time() < min(end_time, safety_end_time)
            # end_time = 0 + 1 = 1.
            # time=0 -> loop
            # time=2.0 -> loop ends
            # Raises "Polling timed out."

            with pytest.raises(CoreasonIdentityError, match="Polling timed out."):
                await client.poll_token(device_resp)
