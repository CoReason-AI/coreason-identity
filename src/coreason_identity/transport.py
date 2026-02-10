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
Transport component for safe HTTP requests with SSRF and DoS protection.
"""

import ipaddress
import json
import socket
from typing import Any

import anyio
import httpx

from coreason_identity.exceptions import CoreasonIdentityError, OversizedResponseError


class SafeAsyncTransport(httpx.AsyncHTTPTransport):
    """
    A custom HTTP transport that performs strict SSRF protection by resolving DNS
    and validating the IP address against a blocklist before connection.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """
        Overrides the request handling to enforce IP validation.
        """
        url = request.url
        hostname = url.host
        port = url.port or (443 if url.scheme == "https" else 80)

        # 1. Resolve DNS (in a thread to avoid blocking)
        try:
            # socket.getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
            # sockaddr is (ip, port) for IPv4/IPv6
            addr_info = await anyio.to_thread.run_sync(socket.getaddrinfo, hostname, port)
            # Use the first resolved address
            if not addr_info:
                raise CoreasonIdentityError(f"No IP address resolved for {hostname}")

            ip_str = addr_info[0][4][0]
        except socket.gaierror as e:
            raise CoreasonIdentityError(f"DNS resolution failed for {hostname}: {e}") from e

        # 2. Validate IP
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError as e:
            raise CoreasonIdentityError(f"Invalid IP address resolved for {hostname}: {ip_str}") from e

        if (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or (ip_obj.is_reserved and str(ip_obj) != "0.0.0.0")
        ):
            raise CoreasonIdentityError(f"SSRF Protection: Blocked connection to restricted IP {ip_str} for {hostname}")

        # 3. Rewrite URL to use IP
        # We replace the hostname in the URL with the IP address.
        # This forces the transport to connect to the IP.
        new_url = url.copy_with(host=ip_str)
        request.url = new_url

        # 4. Set Host header if not already set
        # We need to set it to the ORIGINAL hostname to support virtual hosting.
        if "host" not in request.headers:
            request.headers["host"] = hostname

        # 5. SNI (Server Name Indication)
        # We need to explicitly set the SNI hostname in the extensions.
        request.extensions["sni_hostname"] = hostname

        return await super().handle_async_request(request)


async def safe_json_fetch(
    client: httpx.AsyncClient, url: str, max_bytes: int = 1_000_000, method: str = "GET", **kwargs: Any
) -> Any:
    """
    Fetches a JSON response with strict DoS protection (bounded read).

    Args:
        client: The httpx client to use.
        url: The URL to fetch.
        max_bytes: The maximum allowed size in bytes. Defaults to 1MB.
        method: HTTP method to use. Defaults to "GET".
        **kwargs: Additional arguments passed to client.stream().

    Returns:
        Any: The parsed JSON data.

    Raises:
        OversizedResponseError: If the response exceeds the size limit.
        CoreasonIdentityError: For other HTTP or parsing errors.
    """
    try:
        async with client.stream(method, url, follow_redirects=True, **kwargs) as response:
            response.raise_for_status()

            # Check Content-Length header first
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > max_bytes:
                        raise OversizedResponseError(
                            f"Content-Length {content_length} exceeds limit of {max_bytes} bytes"
                        )
                except ValueError:
                    pass  # Invalid header, ignore and rely on stream check

            content = bytearray()
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) > max_bytes:
                    raise OversizedResponseError(f"Response size exceeds limit of {max_bytes} bytes")

            # Parse JSON
            return json.loads(content)

    except httpx.HTTPError as e:
        raise CoreasonIdentityError(f"HTTP error fetching {url}: {e}") from e
    except json.JSONDecodeError as e:
        raise CoreasonIdentityError(f"Invalid JSON response from {url}: {e}") from e
    except Exception as e:
        if isinstance(e, (OversizedResponseError, CoreasonIdentityError)):
            raise
        raise CoreasonIdentityError(f"Failed to fetch {url}: {e}") from e
