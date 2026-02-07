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


# Mock response for successful requests
MOCK_RESPONSE = httpx.Response(200, json={"status": "ok"})


@pytest.fixture
def mock_getaddrinfo():
    # We patch socket.getaddrinfo specifically for these tests
    # Note: conftest.py might already patch it, but we override it here with a new patch
    # to control the return value per test.
    with patch("socket.getaddrinfo") as mock:
        yield mock


@pytest.mark.asyncio
async def test_safe_transport_blocks_private_ip(mock_getaddrinfo):
    """Test that resolving to a private IP raises a ConnectError."""
    # Mock resolving to 127.0.0.1
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    transport = SafeHTTPTransport()
    client = httpx.AsyncClient(transport=transport)

    with pytest.raises(httpx.ConnectError, match="blocked by security policy"):
        await client.get("https://evil.local")


@pytest.mark.asyncio
async def test_safe_transport_blocks_private_ipv6(mock_getaddrinfo):
    """Test that resolving to a private IPv6 address raises a ConnectError."""
    # Mock resolving to ::1
    mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0))]

    transport = SafeHTTPTransport()
    client = httpx.AsyncClient(transport=transport)

    with pytest.raises(httpx.ConnectError, match="blocked by security policy"):
        await client.get("https://evil.local")


@pytest.mark.asyncio
async def test_safe_transport_allows_public_ip(mock_getaddrinfo):
    """Test that resolving to a public IP allows the request and pins the IP."""
    # Mock resolving to 8.8.8.8
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    transport = SafeHTTPTransport()

    # We patch the parent handle_async_request to verify the modified request
    with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super:
        mock_super.return_value = MOCK_RESPONSE

        client = httpx.AsyncClient(transport=transport)
        response = await client.get("https://google.com")

        assert response.status_code == 200

        # Verify the request passed to super() has the IP in the URL
        args, _ = mock_super.call_args
        request = args[0]
        assert request.url.host == "8.8.8.8"
        # Verify Host header is preserved
        assert request.headers["Host"] == "google.com"
        # Verify SNI extension is set (crucial for SSL verification)
        assert request.extensions.get("sni_hostname") == "google.com"


@pytest.mark.asyncio
async def test_safe_transport_allows_private_ip_in_unsafe_mode(mock_getaddrinfo):
    """Test that unsafe_local_dev allows private IPs."""
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    transport = SafeHTTPTransport(unsafe_local_dev=True)

    with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super:
        mock_super.return_value = MOCK_RESPONSE

        client = httpx.AsyncClient(transport=transport)
        await client.get("https://localhost")

        args, _ = mock_super.call_args
        request = args[0]
        assert request.url.host == "127.0.0.1"
        # SNI should still be set
        assert request.extensions.get("sni_hostname") == "localhost"

@pytest.mark.asyncio
async def test_safe_transport_dns_failure(mock_getaddrinfo):
    """Test that DNS resolution failure raises ConnectError."""
    mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")

    transport = SafeHTTPTransport()
    client = httpx.AsyncClient(transport=transport)

    with pytest.raises(httpx.ConnectError, match="Could not resolve hostname"):
        await client.get("https://nonexistent.domain")


@pytest.mark.asyncio
async def test_safe_transport_ipv6_public(mock_getaddrinfo):
    """Test that public IPv6 is allowed and formatted correctly in URL."""
    # Mock resolving to valid public IPv6: 2001:4860:4860::8888
    mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 443, 0, 0))]

    transport = SafeHTTPTransport()

    with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super:
        mock_super.return_value = MOCK_RESPONSE

        client = httpx.AsyncClient(transport=transport)
        await client.get("https://ipv6.google.com")

        args, _ = mock_super.call_args
        request = args[0]
        # Check IPv6 formatting
        # httpx.URL.host returns the unbracketed IPv6 address
        assert request.url.host == "2001:4860:4860::8888"
        # Verify the full URL string contains brackets
        assert "https://[2001:4860:4860::8888]" in str(request.url)
        assert request.extensions.get("sni_hostname") == "ipv6.google.com"


@pytest.mark.asyncio
async def test_safe_transport_invalid_ip_string(mock_getaddrinfo):
    """Test that invalid IP string from resolver fails validation."""
    # Mock returning garbage as IP (which ipaddress lib rejects)
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("garbage", 443))]

    transport = SafeHTTPTransport()
    client = httpx.AsyncClient(transport=transport)

    # It should fail validation because ipaddress raises ValueError -> returns False
    # So all IPs blocked
    with pytest.raises(httpx.ConnectError, match="blocked by security policy"):
        await client.get("https://garbage.com")

@pytest.mark.asyncio
async def test_safe_transport_invalid_ip_string_unsafe(mock_getaddrinfo):
    """Test that invalid IP string bypasses validation in unsafe mode and is used as-is."""
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("garbage", 443))]

    transport = SafeHTTPTransport(unsafe_local_dev=True)

    with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super:
        mock_super.return_value = MOCK_RESPONSE

        client = httpx.AsyncClient(transport=transport)
        await client.get("https://garbage.com")

        args, _ = mock_super.call_args
        request = args[0]
        # Should use garbage as host because ipaddress parsing failed but we proceeded
        assert request.url.host == "garbage"
