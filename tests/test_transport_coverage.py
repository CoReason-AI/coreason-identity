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
Tests for SafeAsyncTransport coverage.
"""

import socket
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from coreason_identity.exceptions import CoreasonIdentityError, OversizedResponseError
from coreason_identity.transport import SafeAsyncTransport, safe_json_fetch


@pytest.fixture
def mock_getaddrinfo() -> Generator[MagicMock, None, None]:
    with patch("socket.getaddrinfo") as mock:
        yield mock


class TestTransportCoverage:
    @pytest.mark.asyncio
    async def test_handle_async_request_no_resolution(self, mock_getaddrinfo: MagicMock) -> None:
        """Test line 47: No IP address resolved."""
        mock_getaddrinfo.return_value = [] # Empty list

        transport = SafeAsyncTransport()
        request = httpx.Request("GET", "https://test.com")

        with pytest.raises(CoreasonIdentityError, match="No IP address resolved"):
            await transport.handle_async_request(request)

    @pytest.mark.asyncio
    async def test_handle_async_request_dns_error(self, mock_getaddrinfo: MagicMock) -> None:
        """Test lines 50-51: DNS resolution failed."""
        mock_getaddrinfo.side_effect = socket.gaierror("DNS Error")

        transport = SafeAsyncTransport()
        request = httpx.Request("GET", "https://test.com")

        with pytest.raises(CoreasonIdentityError, match="DNS resolution failed"):
            await transport.handle_async_request(request)

    @pytest.mark.asyncio
    async def test_handle_async_request_invalid_ip(self, mock_getaddrinfo: MagicMock) -> None:
        """Test lines 56-57: Invalid IP address resolved (e.g. malformed string)."""
        # socket.getaddrinfo returns malformed IP
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("invalid_ip", 443))]

        transport = SafeAsyncTransport()
        request = httpx.Request("GET", "https://test.com")

        with pytest.raises(CoreasonIdentityError, match="Invalid IP address resolved"):
            await transport.handle_async_request(request)

    @pytest.mark.asyncio
    async def test_handle_async_request_reserved_ip(self, mock_getaddrinfo: MagicMock) -> None:
        """Test line 76: Reserved IP (but not 0.0.0.0)."""
        # 240.0.0.1 is reserved (Class E)
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("240.0.0.1", 443))]

        transport = SafeAsyncTransport()
        request = httpx.Request("GET", "https://test.com")

        with pytest.raises(CoreasonIdentityError, match="SSRF Protection: Blocked"):
            await transport.handle_async_request(request)

    @pytest.mark.asyncio
    async def test_safe_json_fetch_invalid_content_length(self) -> None:
        """Test line 118: Invalid Content-Length header (ignored)."""
        client = httpx.AsyncClient()

        mock_response = MagicMock()
        mock_response.headers = {"Content-Length": "invalid"}
        mock_response.aiter_bytes = MagicMock()
        async def content_stream() -> AsyncGenerator[bytes, None]:
            yield b"{}"
        mock_response.aiter_bytes = content_stream
        mock_response.raise_for_status = MagicMock()

        @asynccontextmanager
        async def mock_stream(*_args: Any, **_kwargs: Any) -> AsyncGenerator[MagicMock, None]:
            yield mock_response

        with patch.object(client, "stream", side_effect=mock_stream):
            # Should succeed despite invalid header
            result = await safe_json_fetch(client, "url")
            assert result == {}

    @pytest.mark.asyncio
    async def test_safe_json_fetch_json_decode_error(self) -> None:
        """Test line 132: JSON decode error."""
        client = httpx.AsyncClient()

        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.aiter_bytes = MagicMock()
        async def content_stream() -> AsyncGenerator[bytes, None]:
            yield b"invalid json"
        mock_response.aiter_bytes = content_stream
        mock_response.raise_for_status = MagicMock()

        @asynccontextmanager
        async def mock_stream(*_args: Any, **_kwargs: Any) -> AsyncGenerator[MagicMock, None]:
            yield mock_response

        with patch.object(client, "stream", side_effect=mock_stream):
            with pytest.raises(CoreasonIdentityError, match="Invalid JSON response"):
                await safe_json_fetch(client, "url")

    @pytest.mark.asyncio
    async def test_safe_json_fetch_generic_exception(self) -> None:
        """Test line 136: Generic exception."""
        client = httpx.AsyncClient()

        # Mock stream to raise generic exception
        @asynccontextmanager
        async def mock_stream(*_args: Any, **_kwargs: Any) -> AsyncGenerator[MagicMock, None]:
            raise ValueError("Generic error")
            yield MagicMock() # Unreachable

        with patch.object(client, "stream", side_effect=mock_stream):
            with pytest.raises(CoreasonIdentityError, match="Failed to fetch"):
                await safe_json_fetch(client, "url")
