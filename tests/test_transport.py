# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import socket
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from coreason_identity.transport import SafeHTTPTransport


@pytest.mark.asyncio
async def test_safe_transport_blocks_private_ip() -> None:
    """Test that SafeHTTPTransport blocks private IPs."""
    # Mock socket.getaddrinfo to return a private IP
    private_ip = "192.168.1.1"
    mock_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (private_ip, 443))]

    transport = SafeHTTPTransport()

    with patch("socket.getaddrinfo", return_value=mock_addr_info):
        request = httpx.Request("GET", "https://private.local/foo")

        with pytest.raises(httpx.ConnectError, match=r"All resolved IPs .* are blocked"):
            await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_safe_transport_allows_public_ip() -> None:
    """Test that SafeHTTPTransport allows public IPs and modifies the request."""
    public_ip = "8.8.8.8"
    mock_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (public_ip, 443))]

    transport = SafeHTTPTransport()

    # Mock super().handle_async_request to avoid actual network call
    # We use AsyncMock for the return value of handle_async_request because it's awaitable
    with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super:
        # The result of awaiting the mock should be the response
        mock_super.return_value = httpx.Response(200)

        with patch("socket.getaddrinfo", return_value=mock_addr_info):
            request = httpx.Request("GET", "https://public.example.com/foo")
            await transport.handle_async_request(request)

            # Verify super called
            assert mock_super.called
            called_request = mock_super.call_args[0][0]

            # Verify URL host is now the IP
            assert called_request.url.host == public_ip
            # Verify headers contain original host
            assert called_request.headers["Host"] == "public.example.com"
            # Verify SNI extension
            assert called_request.extensions["sni_hostname"] == "public.example.com"


@pytest.mark.asyncio
async def test_safe_transport_dns_failure() -> None:
    """Test DNS resolution failure handling."""
    transport = SafeHTTPTransport()

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        request = httpx.Request("GET", "https://nonexistent.local")
        with pytest.raises(httpx.ConnectError, match="Could not resolve hostname"):
            await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_safe_transport_ipv6() -> None:
    """Test IPv6 handling."""
    # IPv6 example
    ip_v6 = "2001:4860:4860::8888"
    mock_addr_info = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip_v6, 443, 0, 0))]

    transport = SafeHTTPTransport()

    with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super:
        mock_super.return_value = httpx.Response(200)

        with patch("socket.getaddrinfo", return_value=mock_addr_info):
            request = httpx.Request("GET", "https://ipv6.example.com")
            await transport.handle_async_request(request)

            called_request = mock_super.call_args[0][0]
            # httpx normalizes URL host, usually unbracketed if it parses it?
            # Or keeps it. Assert logic matches observed behavior.
            assert called_request.url.host == ip_v6


@pytest.mark.asyncio
async def test_safe_transport_invalid_ip_string() -> None:
    """Test invalid IP string logic (defensive coding)."""
    # If getaddrinfo returns garbage (should not happen realistically but for coverage)
    mock_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("not-an-ip", 443))]

    transport = SafeHTTPTransport()

    with patch("socket.getaddrinfo", return_value=mock_addr_info):
        request = httpx.Request("GET", "https://bad.example.com")
        # Should be blocked because _validate_ip returns False for invalid IPs
        with pytest.raises(httpx.ConnectError, match=r"All resolved IPs .* are blocked"):
            await transport.handle_async_request(request)
