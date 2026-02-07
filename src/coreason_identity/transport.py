# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import ipaddress
import socket
from typing import Any

import anyio
import httpx


class SafeHTTPTransport(httpx.AsyncHTTPTransport):
    """
    A custom transport that enforces DNS pinning and IP validation to prevent SSRF/TOCTOU attacks.
    It resolves the hostname to an IP, validates the IP against a blocklist, and then forces
    the connection to that specific IP while preserving SSL/SNI verification.
    """

    def __init__(self, unsafe_local_dev: bool = False, **kwargs: Any) -> None:
        """
        Initialize the SafeHTTPTransport.

        Args:
            unsafe_local_dev: If True, allows connections to private/loopback IPs.
            **kwargs: Arguments passed to httpx.AsyncHTTPTransport.
        """
        self.unsafe_local_dev = unsafe_local_dev
        super().__init__(**kwargs)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """
        Overrides the request handling to implement DNS pinning and IP validation.
        """
        # Extract the original hostname
        hostname = request.url.host

        # Resolve the hostname to an IP address
        # Run DNS resolution in a thread to avoid blocking the event loop
        try:
            # socket.getaddrinfo returns a list of (family, type, proto, canonname, sockaddr)
            addr_infos = await anyio.to_thread.run_sync(
                socket.getaddrinfo, hostname, None
            )
        except socket.gaierror as e:
            raise httpx.ConnectError(f"Could not resolve hostname: {hostname}") from e

        # Select the first valid IP and validate it
        ip_str: str | None = None
        for _, _, _, _, sockaddr in addr_infos:
            # sockaddr is (ip, port) for IPv4 or (ip, port, flowinfo, scopeid) for IPv6
            current_ip = sockaddr[0]
            if self._validate_ip(current_ip):
                ip_str = current_ip
                break

        if not ip_str:
            raise httpx.ConnectError(
                f"All resolved IPs for {hostname} are blocked by security policy."
            )

        # Modify the request URL to use the IP address
        # Handle IPv6 formatting for URL (needs brackets)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv6Address):
                host_replacement = f"[{ip_str}]"
            else:
                host_replacement = ip_str
        except ValueError:
            # Should not happen if getaddrinfo returned it
            host_replacement = ip_str

        # Create a new URL with the IP
        new_url = request.url.copy_with(host=host_replacement)
        request.url = new_url

        # Set the Host header to the original hostname
        request.headers["Host"] = hostname

        # Attempt to pass SNI hostname via extensions (supported by some httpcore versions)
        # This tells httpcore to use 'hostname' for SNI and for SSL validation
        # even though we are connecting to 'ip_str'.
        # This avoids the need for manual SSL verification and custom contexts.
        request.extensions["sni_hostname"] = hostname

        # Perform the request
        return await super().handle_async_request(request)

    def _validate_ip(self, ip_str: str) -> bool:
        """
        Validates if an IP is allowed based on the configuration.
        Returns True if allowed, False otherwise.
        """
        # If unsafe local dev is enabled, allow everything (except maybe 0.0.0.0?)
        # The requirement says "Allow private IPs *only if* unsafe_local_dev is True"
        if self.unsafe_local_dev:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
            ):
                return False
        except ValueError:
            return False

        return True
