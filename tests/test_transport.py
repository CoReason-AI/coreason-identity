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
Tests for the SafeAsyncTransport component.
"""

import json
import socket
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from coreason_identity.exceptions import CoreasonIdentityError, OversizedResponseError
from coreason_identity.transport import SafeAsyncTransport, safe_json_fetch


@pytest.fixture
def mock_getaddrinfo() -> Generator[MagicMock, None, None]:
    with patch("socket.getaddrinfo") as mock:
        yield mock


@pytest.mark.asyncio
async def test_safe_transport_blocks_private_ip(mock_getaddrinfo: MagicMock) -> None:
    # Mock DNS resolving to a private IP
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 443))]

    transport = SafeAsyncTransport()
    request = httpx.Request("GET", "https://internal.local/data")

    with pytest.raises(CoreasonIdentityError, match="SSRF Protection: Blocked"):
        await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_safe_transport_allows_public_ip(mock_getaddrinfo: MagicMock) -> None:
    # Mock DNS resolving to a public IP
    # 8.8.8.8 is Google DNS, safe public IP
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    transport = SafeAsyncTransport()
    # Mock super().handle_async_request to avoid actual network call
    with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super:
        mock_super.return_value = httpx.Response(200)

        request = httpx.Request("GET", "https://google.com")
        await transport.handle_async_request(request)

        # Verify IP was rewritten in URL
        assert request.url.host == "8.8.8.8"
        # Verify SNI and Host header preserved
        assert request.headers["host"] == "google.com"
        assert request.extensions["sni_hostname"] == "google.com"


@pytest.mark.asyncio
async def test_safe_json_fetch_limit() -> None:
    client = httpx.AsyncClient()

    # Mock stream to return infinite data
    async def infinite_stream() -> AsyncGenerator[bytes, None]:
        while True:
            yield b"a" * 1024

    mock_response = MagicMock()
    mock_response.headers = {}
    mock_response.aiter_bytes = infinite_stream
    mock_response.raise_for_status = MagicMock()

    # Context manager mock
    @asynccontextmanager
    async def mock_stream(*_: Any, **__: Any) -> AsyncGenerator[MagicMock, None]:
        yield mock_response

    with (
        patch.object(client, "stream", side_effect=mock_stream),
        pytest.raises(OversizedResponseError),
    ):
        await safe_json_fetch(client, "http://test.com", max_bytes=5000)


@pytest.mark.asyncio
async def test_safe_json_fetch_content_length_limit() -> None:
    client = httpx.AsyncClient()

    mock_response = MagicMock()
    # Header claims 2MB
    mock_response.headers = {"Content-Length": str(2 * 1024 * 1024)}

    @asynccontextmanager
    async def mock_stream(*_: Any, **__: Any) -> AsyncGenerator[MagicMock, None]:
        yield mock_response

    with (
        patch.object(client, "stream", side_effect=mock_stream),
        pytest.raises(OversizedResponseError, match="exceeds limit"),
    ):
        await safe_json_fetch(client, "http://test.com", max_bytes=1_000_000)


@pytest.mark.asyncio
async def test_safe_transport_blocks_loopback_ipv6(mock_getaddrinfo: MagicMock) -> None:
    # IPv6 Loopback ::1
    mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0))]

    transport = SafeAsyncTransport()
    request = httpx.Request("GET", "https://localhost/")

    with pytest.raises(CoreasonIdentityError, match="SSRF Protection: Blocked"):
        await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_safe_transport_blocks_link_local(mock_getaddrinfo: MagicMock) -> None:
    # Link Local 169.254.x.x
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]

    transport = SafeAsyncTransport()
    request = httpx.Request("GET", "http://metadata/")

    with pytest.raises(CoreasonIdentityError, match="SSRF Protection: Blocked"):
        await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_safe_json_fetch_exact_limit() -> None:
    """Test safe_json_fetch where content is exactly the limit."""
    client = httpx.AsyncClient()
    limit = 10
    content = b'{"a": 123}'  # 10 bytes

    mock_response = MagicMock()
    mock_response.headers = {"Content-Length": str(limit)}
    mock_response.aiter_bytes = MagicMock()

    async def content_stream() -> AsyncGenerator[bytes, None]:
        yield content

    mock_response.aiter_bytes = content_stream
    mock_response.raise_for_status = MagicMock()

    @asynccontextmanager
    async def mock_stream(*_: Any, **__: Any) -> AsyncGenerator[MagicMock, None]:
        yield mock_response

    with patch.object(client, "stream", side_effect=mock_stream):
        result = await safe_json_fetch(client, "http://test.com", max_bytes=limit)
        assert result == {"a": 123}


@pytest.mark.asyncio
async def test_safe_json_fetch_chunked_limit_exceeded() -> None:
    """Test chunked encoding where many small chunks exceed limit."""
    client = httpx.AsyncClient()
    limit = 10

    mock_response = MagicMock()
    mock_response.headers = {}  # No content length
    mock_response.raise_for_status = MagicMock()

    async def content_stream() -> AsyncGenerator[bytes, None]:
        yield b"12345"
        yield b"67890"  # Total 10 (still OK)
        yield b"1"  # Total 11 (Fail)

    mock_response.aiter_bytes = content_stream

    @asynccontextmanager
    async def mock_stream(*_: Any, **__: Any) -> AsyncGenerator[MagicMock, None]:
        yield mock_response

    with (
        patch.object(client, "stream", side_effect=mock_stream),
        pytest.raises(OversizedResponseError, match="Response size exceeds limit"),
    ):
        await safe_json_fetch(client, "http://test.com", max_bytes=limit)


@pytest.mark.asyncio
async def test_safe_transport_dns_empty(mock_getaddrinfo: MagicMock) -> None:
    """Test that empty DNS resolution raises CoreasonIdentityError."""
    mock_getaddrinfo.return_value = []
    transport = SafeAsyncTransport()
    request = httpx.Request("GET", "https://example.com")

    with pytest.raises(CoreasonIdentityError, match="No IP address resolved"):
        await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_safe_transport_dns_error(mock_getaddrinfo: MagicMock) -> None:
    """Test that DNS resolution error is wrapped in CoreasonIdentityError."""
    mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
    transport = SafeAsyncTransport()
    request = httpx.Request("GET", "https://example.com")

    with pytest.raises(CoreasonIdentityError, match="DNS resolution failed"):
        await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_safe_transport_invalid_ip(mock_getaddrinfo: MagicMock) -> None:
    """Test that invalid IP returned by DNS raises CoreasonIdentityError."""
    # getaddrinfo returns a tuple where index 4 is sockaddr, and index 0 of that is IP
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("invalid_ip", 443))]
    transport = SafeAsyncTransport()
    request = httpx.Request("GET", "https://example.com")

    with pytest.raises(CoreasonIdentityError, match="Invalid IP address resolved"):
        await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_safe_json_fetch_invalid_content_length() -> None:
    """Test that invalid Content-Length is ignored and stream limit is used."""
    client = httpx.AsyncClient()
    mock_response = MagicMock()
    mock_response.headers = {"Content-Length": "not-an-integer"}
    mock_response.raise_for_status = MagicMock()

    async def content_stream() -> AsyncGenerator[bytes, None]:
        yield b'{"a": 1}'

    mock_response.aiter_bytes = content_stream

    @asynccontextmanager
    async def mock_stream(*_: Any, **__: Any) -> AsyncGenerator[MagicMock, None]:
        yield mock_response

    with patch.object(client, "stream", side_effect=mock_stream):
        # Should succeed because actual content is small, and invalid header is ignored
        result = await safe_json_fetch(client, "http://test.com")
        assert result == {"a": 1}


@pytest.mark.asyncio
async def test_safe_json_fetch_invalid_json() -> None:
    """Test that invalid JSON response raises CoreasonIdentityError."""
    client = httpx.AsyncClient()
    mock_response = MagicMock()
    mock_response.headers = {}
    mock_response.raise_for_status = MagicMock()

    async def content_stream() -> AsyncGenerator[bytes, None]:
        yield b"not valid json"

    mock_response.aiter_bytes = content_stream

    @asynccontextmanager
    async def mock_stream(*_: Any, **__: Any) -> AsyncGenerator[MagicMock, None]:
        yield mock_response

    with (
        patch.object(client, "stream", side_effect=mock_stream),
        pytest.raises(CoreasonIdentityError, match="Invalid JSON response"),
    ):
        await safe_json_fetch(client, "http://test.com")


@pytest.mark.asyncio
async def test_safe_json_fetch_generic_error() -> None:
    """Test that generic exceptions are wrapped in CoreasonIdentityError."""
    client = httpx.AsyncClient()

    @asynccontextmanager
    async def mock_stream(*_: Any, **__: Any) -> AsyncGenerator[MagicMock, None]:
        raise ValueError("Something unexpected")
        yield MagicMock()  # Unreachable but needed for typing if not analyzing flow

    with (
        patch.object(client, "stream", side_effect=mock_stream),
        pytest.raises(CoreasonIdentityError, match="Failed to fetch"),
    ):
        await safe_json_fetch(client, "http://test.com")


@pytest.mark.asyncio
async def test_safe_transport_adds_host_header(mock_getaddrinfo: MagicMock) -> None:
    """Test that Host header is added if missing."""
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    transport = SafeAsyncTransport()

    # Mock super().handle_async_request
    with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super:
        mock_super.return_value = httpx.Response(200)

        # Case 1: Header missing
        request = httpx.Request("GET", "https://example.com")
        # Ensure it's not set by httpx default logic for this test (though request object has it implicitly usually)
        if "host" in request.headers:
            del request.headers["host"]

        await transport.handle_async_request(request)
        assert request.headers["host"] == "example.com"

        # Case 2: Header present
        request = httpx.Request("GET", "https://example.com")
        request.headers["host"] = "custom.host"
        await transport.handle_async_request(request)
        assert request.headers["host"] == "custom.host"


@pytest.mark.asyncio
async def test_safe_json_fetch_http_error() -> None:
    """Test that HTTPError is wrapped in CoreasonIdentityError."""
    client = httpx.AsyncClient()

    @asynccontextmanager
    async def mock_stream(*_: Any, **__: Any) -> AsyncGenerator[MagicMock, None]:
        raise httpx.HTTPError("Connection failed")
        yield MagicMock()

    with (
        patch.object(client, "stream", side_effect=mock_stream),
        pytest.raises(CoreasonIdentityError, match="HTTP error fetching"),
    ):
        await safe_json_fetch(client, "http://test.com")
