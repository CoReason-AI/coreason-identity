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

import anyio
import httpx
import pytest

from coreason_identity.transport import SafeHTTPTransport


def mock_addr_info(
    ip: str,
) -> list[
    tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str | int, int] | tuple[str | int, int, int, int]]
]:
    """Helper to generate a mock getaddrinfo response."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    if family == socket.AF_INET6:
        return [(family, socket.SOCK_STREAM, 6, "", (ip, 443, 0, 0))]
    return [(family, socket.SOCK_STREAM, 6, "", (ip, 443))]


class TestSSRFComplexCases:
    """
    Tests covering complex scenarios for SSRF protection and SafeHTTPTransport.
    """

    @pytest.mark.asyncio
    async def test_environment_toggling_workflow(self) -> None:
        """
        Verify that the validation logic correctly respects the environment variable
        changing dynamically (simulating config reloads or environment shifts in tests).
        """
        unsafe_domain = "localhost"
        safe_ip_mock = mock_addr_info("127.0.0.1")  # Real resolution of localhost is unsafe

        # 1. Start Secure (Default) -> Should Fail
        transport = SafeHTTPTransport(unsafe_local_dev=False)
        client = httpx.AsyncClient(transport=transport)
        with (
            patch("socket.getaddrinfo", return_value=safe_ip_mock),
            pytest.raises(httpx.ConnectError, match="blocked by security policy"),
        ):
            await client.get(f"https://{unsafe_domain}")

        # 2. Re-initialize with Unsafe Mode -> Should Succeed
        transport_unsafe = SafeHTTPTransport(unsafe_local_dev=True)
        client_unsafe = httpx.AsyncClient(transport=transport_unsafe)
        with (
            patch("socket.getaddrinfo", return_value=safe_ip_mock),
            patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super,
        ):
            mock_super.return_value = httpx.Response(200)
            await client_unsafe.get(f"https://{unsafe_domain}")

            # Should have proceeded
            mock_super.assert_called_once()
            args, _ = mock_super.call_args
            request = args[0]
            assert request.url.host == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_dns_flake_then_success_fail_closed(self) -> None:
        """
        Simulate a flaky DNS resolver that first raises an error, then resolves to an unsafe IP.
        This verifies that we fail closed on the first error and don't accidentally pass
        if retries were implemented (which they aren't, but this ensures robust behavior).
        """
        transport = SafeHTTPTransport()
        client = httpx.AsyncClient(transport=transport)

        # First call raises error
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.side_effect = [socket.gaierror("Temporary failure"), mock_addr_info("127.0.0.1")]

            # Attempt 1: Should fail due to DNS error
            with pytest.raises(httpx.ConnectError, match="Could not resolve hostname"):
                await client.get("https://flaky.dns")

            # Attempt 2: Should fail due to Security Policy (blocked IP)
            # Note: side_effect iterator was advanced by the first call, so next call
            # returns mock_addr_info("127.0.0.1")

            with pytest.raises(httpx.ConnectError, match="blocked by security policy"):
                await client.get("https://flaky.dns")

    @pytest.mark.asyncio
    async def test_recursive_cname_chain_resolution(self) -> None:
        """
        Test a scenario where CNAMEs might lead to a safe IP then an unsafe one?
        Actually socket.getaddrinfo does the recursion.
        We simulate getaddrinfo returning multiple entries representing the chain logic
        (though usually it just returns the final IPs).
        We ensure that if the FINAL resolved IP is unsafe, it fails.
        """
        # Scenario: public.cname -> internal.cname -> 192.168.1.1
        final_resolution = mock_addr_info("192.168.1.1")

        with patch("socket.getaddrinfo", return_value=final_resolution):
            transport = SafeHTTPTransport()
            client = httpx.AsyncClient(transport=transport)

            with pytest.raises(httpx.ConnectError, match="blocked by security policy"):
                await client.get("https://recursive.cname")

    @pytest.mark.asyncio
    async def test_concurrent_requests_mixed_security(self) -> None:
        """
        Test concurrent requests where one resolves to SAFE and one to UNSAFE IP.
        Verify that the safe one succeeds and the unsafe one is blocked independently.
        """
        # Domain A -> 8.8.8.8 (Safe)
        # Domain B -> 127.0.0.1 (Unsafe)

        transport = SafeHTTPTransport()
        client = httpx.AsyncClient(transport=transport)

        # We need a robust mock that checks arguments
        def mock_resolver(
            host: str, *args: list[Any], **kwargs: dict[str, Any]
        ) -> list[
            tuple[
                socket.AddressFamily,
                socket.SocketKind,
                int,
                str,
                tuple[str | int, int] | tuple[str | int, int, int, int],
            ]
        ]:
            del args, kwargs
            # Simulate DNS response based on host
            if "unsafe.com" in host:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
            # Default/Safe
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

        with (
            patch("socket.getaddrinfo", side_effect=mock_resolver),
            patch("httpx.AsyncHTTPTransport.handle_async_request", new_callable=AsyncMock) as mock_super,
        ):

            async def safe_req() -> None:
                # Simulate successful response for safe request
                mock_super.return_value = httpx.Response(200)
                await client.get("https://safe.com")

            async def unsafe_req() -> None:
                # This should raise ConnectError inside SafeHTTPTransport BEFORE calling handle_async_request
                with pytest.raises(httpx.ConnectError, match="blocked by security policy"):
                    await client.get("https://unsafe.com")

            async with anyio.create_task_group() as tg:
                tg.start_soon(safe_req)
                tg.start_soon(unsafe_req)

            # Verify safe request passed
            # We can check call args to ensure safe.com was processed
            safe_calls = [c for c in mock_super.call_args_list if c[0][0].headers["Host"] == "safe.com"]
            assert len(safe_calls) == 1
