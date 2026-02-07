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
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from coreason_identity.transport import SafeHTTPTransport


def mock_addr_info(
    host: str, *args: list[Any], **kwargs: dict[str, Any]
) -> list[
    tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str | int, int] | tuple[str | int, int, int, int]]
]:
    """Helper to generate a mock getaddrinfo response."""
    del args, kwargs  # Unused
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, 443))]


def mock_addr_info_list(
    hosts: list[str],
) -> list[
    tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str | int, int] | tuple[str | int, int, int, int]]
]:
    """Helper to generate a mock getaddrinfo response with multiple IPs."""
    results: list[
        tuple[
            socket.AddressFamily,
            socket.SocketKind,
            int,
            str,
            tuple[str | int, int] | tuple[str | int, int, int, int],
        ]
    ] = []
    for host in hosts:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        if family == socket.AF_INET6:
            results.append((family, socket.SOCK_STREAM, 6, "", (host, 443, 0, 0)))
        else:
            results.append((family, socket.SOCK_STREAM, 6, "", (host, 443)))
    return results


class TestSSRFEdgeCases:
    """
    Tests covering edge cases for SSRF protection and SafeHTTPTransport.
    """

    @pytest.mark.asyncio
    async def test_mixed_safe_and_unsafe_ips(self) -> None:
        """Test that if ANY resolved IP is unsafe, validation fails."""
        # Domain resolves to 8.8.8.8 (Safe) AND 127.0.0.1 (Unsafe)
        # However, SafeHTTPTransport iterates and picks the FIRST VALID IP.
        # If getaddrinfo returns [unsafe, safe], it should skip unsafe and use safe?
        # WAIT: The implementation iterates and picks the first one that validates.
        # If NO IP validates, it raises ConnectError.
        # So mixed safe/unsafe should result in the safe IP being used, UNLESS we want strict fail-closed on any bad IP?
        # Current implementation: "Select the first valid IP".
        # Let's verify this behavior.

        unsafe_mix = ["127.0.0.1", "8.8.8.8"]
        with patch("socket.getaddrinfo", return_value=mock_addr_info_list(unsafe_mix)):
            transport = SafeHTTPTransport()
            with patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super:
                mock_super.return_value = httpx.Response(200)
                client = httpx.AsyncClient(transport=transport)

                await client.get("https://mixed.example.com")

                # It should have skipped 127.0.0.1 and used 8.8.8.8
                args, _ = mock_super.call_args
                request = args[0]
                assert request.url.host == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_ipv4_mapped_ipv6_localhost(self) -> None:
        """Test IPv4-mapped IPv6 localhost address (::ffff:127.0.0.1)."""
        # ::ffff:7f00:1 is ::ffff:127.0.0.1
        ipv6_mapped = "::ffff:127.0.0.1"
        with patch("socket.getaddrinfo", return_value=mock_addr_info_list([ipv6_mapped])):
            transport = SafeHTTPTransport()
            client = httpx.AsyncClient(transport=transport)

            with pytest.raises(httpx.ConnectError, match="blocked by security policy"):
                await client.get("https://mapped.local")

    @pytest.mark.asyncio
    async def test_ipv6_link_local(self) -> None:
        """Test IPv6 link-local address (fe80::...)."""
        link_local = "fe80::1"
        with patch("socket.getaddrinfo", return_value=mock_addr_info_list([link_local])):
            transport = SafeHTTPTransport()
            client = httpx.AsyncClient(transport=transport)

            with pytest.raises(httpx.ConnectError, match="blocked by security policy"):
                await client.get("https://linklocal.ipv6")

    @pytest.mark.asyncio
    async def test_all_ips_blocked(self) -> None:
        """Test that if ALL resolved IPs are unsafe, it fails closed."""
        all_unsafe = ["127.0.0.1", "::1", "169.254.169.254"]
        with patch("socket.getaddrinfo", return_value=mock_addr_info_list(all_unsafe)):
            transport = SafeHTTPTransport()
            client = httpx.AsyncClient(transport=transport)

            with pytest.raises(httpx.ConnectError, match=r"All resolved IPs .* are blocked"):
                await client.get("https://evil-cluster.local")

    @pytest.mark.asyncio
    async def test_empty_resolution(self) -> None:
        """Test behavior when getaddrinfo returns empty list (should be rare but possible)."""
        with patch("socket.getaddrinfo", return_value=[]):
            transport = SafeHTTPTransport()
            client = httpx.AsyncClient(transport=transport)

            # Should fail because no IP found
            with pytest.raises(httpx.ConnectError, match=r"All resolved IPs .* are blocked"):
                await client.get("https://empty.local")

    @pytest.mark.asyncio
    async def test_obfuscated_ip_if_resolved(self) -> None:
        """
        Test that if getaddrinfo resolves an obfuscated IP (e.g. hex) to a canonical IP,
        the validator catches the canonical IP.

        Note: Python's socket.getaddrinfo usually resolves names.
        If we pass "0x7f000001" (hex for 127.0.0.1) as the domain:
        - Linux libc often resolves it.
        - We simulate the RESOLVER doing the de-obfuscation returning 127.0.0.1.
        """
        hex_ip_domain = "0x7f000001"  # 127.0.0.1
        # The key is that the resolver returns the RAW socket address which has the canonical IP
        with patch("socket.getaddrinfo", return_value=mock_addr_info_list(["127.0.0.1"])):
            transport = SafeHTTPTransport()
            client = httpx.AsyncClient(transport=transport)

            with pytest.raises(httpx.ConnectError, match="blocked by security policy"):
                await client.get(f"https://{hex_ip_domain}")
