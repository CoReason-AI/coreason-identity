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

from coreason_identity.transport import SafeHTTPTransport, SecurityError


@pytest.fixture
def transport():
    return SafeHTTPTransport()


@pytest.mark.asyncio
async def test_transport_allows_public_dns(transport):
    """
    Test that the transport resolves a public DNS to an IP and pins the connection,
    preserving Host header and SNI.
    """
    request = httpx.Request("GET", "https://example.com/foo")

    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        # Return a public IP (TEST-NET-3: 203.0.113.0/24 is reserved for documentation but public-like routing-wise,
        # but 93.184.216.34 (example.com) is safe.
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]

        with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super_handle:
            mock_super_handle.return_value = httpx.Response(200)

            response = await transport.handle_async_request(request)

            assert response.status_code == 200

            # Verify modifications
            call_args = mock_super_handle.call_args
            assert call_args is not None
            modified_request = call_args[0][0]

            # URL host should be the IP
            assert str(modified_request.url) == "https://93.184.216.34/foo"

            # Host header should be the original hostname
            assert modified_request.headers["Host"] == "example.com"

            # SNI extension should be the original hostname
            assert modified_request.extensions["sni_hostname"] == "example.com"


@pytest.mark.asyncio
async def test_transport_blocks_private_dns(transport):
    """
    Test that the transport raises SecurityError if the domain resolves to a private IP.
    """
    request = httpx.Request("GET", "https://internal.corp")

    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        # Return a private IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0))
        ]

        with pytest.raises(SecurityError, match="Security violation"):
            await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_transport_blocks_loopback_ipv6(transport):
    """
    Test that the transport raises SecurityError if the domain resolves to an IPv6 loopback.
    """
    request = httpx.Request("GET", "https://localhost6")

    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0))
        ]

        with pytest.raises(SecurityError, match="Security violation"):
            await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_transport_dns_resolution_failure(transport):
    """
    Test that the transport raises SecurityError if DNS resolution fails.
    """
    request = httpx.Request("GET", "https://invalid.domain")

    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")

        with pytest.raises(SecurityError, match="DNS resolution failed"):
            await transport.handle_async_request(request)


@pytest.mark.asyncio
async def test_transport_direct_ip_blocked(transport):
    """
    Test that the transport raises SecurityError if a private IP is used directly in the URL.
    """
    request = httpx.Request("GET", "https://127.0.0.1")

    # No DNS resolution should happen
    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        with pytest.raises(SecurityError, match="Access to 127.0.0.1 .* is blocked"):
            await transport.handle_async_request(request)

        mock_getaddrinfo.assert_not_called()


@pytest.mark.asyncio
async def test_transport_direct_ip_allowed(transport):
    """
    Test that the transport allows a public IP used directly in the URL.
    """
    request = httpx.Request("GET", "https://8.8.8.8")

    with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super_handle:
        mock_super_handle.return_value = httpx.Response(200)

        await transport.handle_async_request(request)

        mock_super_handle.assert_called_once()
        # Verify no SNI forcing happens for direct IP
        call_args = mock_super_handle.call_args
        modified_request = call_args[0][0]
        assert "sni_hostname" not in modified_request.extensions


@pytest.mark.asyncio
async def test_transport_explicit_port_preservation(transport):
    """
    Test that the transport preserves the port when rewriting the URL.
    """
    request = httpx.Request("GET", "https://example.com:8443/foo")

    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]

        with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super_handle:
            mock_super_handle.return_value = httpx.Response(200)

            await transport.handle_async_request(request)

            call_args = mock_super_handle.call_args
            modified_request = call_args[0][0]

            # Port should be preserved
            assert str(modified_request.url) == "https://93.184.216.34:8443/foo"
            assert modified_request.headers["Host"] == "example.com:8443"


@pytest.mark.asyncio
async def test_transport_adds_host_header_if_missing(transport):
    """
    Test that the transport adds Host header if missing.
    """
    request = httpx.Request("GET", "https://example.com/foo")
    # Explicitly remove Host header
    if "host" in request.headers:
        del request.headers["host"]

    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]

        with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super_handle:
            mock_super_handle.return_value = httpx.Response(200)

            await transport.handle_async_request(request)

            call_args = mock_super_handle.call_args
            modified_request = call_args[0][0]

            assert modified_request.headers["Host"] == "example.com"


@pytest.mark.asyncio
async def test_transport_ignores_invalid_ip_format(transport):
    """
    Test that the transport ignores invalid IP formats returned by getaddrinfo.
    """
    request = httpx.Request("GET", "https://example.com")

    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        # Return an invalid IP string mixed with a valid one
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("invalid-ip", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]

        with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super_handle:
            mock_super_handle.return_value = httpx.Response(200)

            await transport.handle_async_request(request)

            # It should skip the invalid one and use the valid one
            call_args = mock_super_handle.call_args
            modified_request = call_args[0][0]
            assert str(modified_request.url) == "https://93.184.216.34"
