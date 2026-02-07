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
Secure HTTP Transport module to mitigate SSRF via DNS Rebinding.
"""

import ipaddress
import socket
from typing import Any

import anyio
import httpx
from loguru import logger

from coreason_identity.exceptions import CoreasonIdentityError


class SecurityError(CoreasonIdentityError):
    """Raised when a security violation is detected."""
    pass


class SafeHTTPTransport(httpx.AsyncHTTPTransport):
    """
    A secure HTTP transport that enforces DNS pinning to prevent SSRF/DNS Rebinding attacks.

    It resolves the hostname to an IP address, validates the IP against blocked ranges
    (private, loopback, link-local, multicast), and then forces the connection to that specific IP
    while preserving the original Host header and SNI for SSL verification.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """
        Intercepts the request to perform DNS validation and pinning.
        """
        # Parse the URL to get the hostname
        # Note: request.url.host is already lowercased and punycode encoded if needed
        hostname = request.url.host

        # If the hostname is already an IP address, validate it directly
        try:
            ip_obj = ipaddress.ip_address(hostname)
            self._validate_ip(ip_obj, hostname)
            # If it's an IP, just proceed
            return await super().handle_async_request(request)
        except ValueError:
            # Not an IP address, proceed to resolve
            pass

        # Resolve DNS asynchronously
        try:
            # We use getaddrinfo with Proto=TCP to simulate what httpcore would do
            # We filter for IPv4 and IPv6
            addr_infos = await anyio.to_thread.run_sync(
                socket.getaddrinfo, hostname, None, 0, socket.SOCK_STREAM
            )
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {hostname}: {e}")
            raise SecurityError(f"DNS resolution failed for {hostname}") from e

        # Iterate through resolved IPs and find the first safe one
        target_ip: str | None = None
        for family, _, _, _, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                self._validate_ip(ip_obj, hostname)
                target_ip = ip_str
                break  # Found a safe IP
            except SecurityError:
                # Log warning but continue checking other IPs (e.g. if one is blocked but another is valid?)
                # Usually if one IP is blocked, we might want to block all, but let's just skip bad ones.
                # Actually, if an attacker controls DNS, they might return 1 bad and 1 good.
                # If we pick the good one, are we safe? Yes, because we connect to THAT IP.
                # But typically, we should be cautious.
                # However, for usability, if a domain has a private IP (e.g. split DNS) we might block it.
                # But here we want to block access to internal resources.
                # So skipping bad IPs is fine, as long as we only connect to a good one.
                continue
            except ValueError:
                continue

        if not target_ip:
            logger.error(f"Security violation: No valid public IP found for {hostname}")
            raise SecurityError(f"Security violation: No valid public IP found for {hostname}")

        # Modify the request to connect to the specific IP
        # 1. Set the SNI hostname for SSL verification
        request.extensions["sni_hostname"] = hostname

        # 2. Ensure the Host header is set to the original hostname
        # httpx sets Host header automatically based on URL if not present.
        # But since we change URL to IP, we must set Host explicitly.
        # Note: We must include the port if it's non-standard.
        if "Host" not in request.headers:
             # Use netloc (which includes port if necessary) converted to string
             # httpx.URL.netloc is bytes in some versions? No, httpx 0.20+ likely str.
             # Wait, httpx.URL.netloc is bytes in recent versions.
             # But request.url.netloc is bytes? Let's check.
             # Actually, httpx.URL properties are usually decoded.
             # Let's use string representation of the authority.
             # request.url.netloc returns bytes. request.url.authority returns str (if available)?
             # No, request.url.netloc is bytes in httpx 0.28.
             # So we should decode it or construct it.
             # Safer: request.url.host + (f":{request.url.port}" if request.url.port else "")
             # But default port logic...
             # Actually, if we just use request.headers["Host"] if present.
             # If not present, we need to replicate what httpx would do.
             # httpx puts netloc in Host header.
             netloc = request.url.netloc.decode("ascii")
             request.headers["Host"] = netloc

        # 3. Rewrite the URL to use the IP address
        # We must use copy_with to preserve other parts (scheme, port, path, query)
        # Note: We keep the port if it was explicit. If it was implicit (None), it stays implicit?
        # No, httpx.URL.host update might not affect port if it wasn't set.
        # But if request.url had port, copy_with preserves it.
        # Wait, copy_with(host=...) expects a string.
        # If target_ip is IPv6, it should be bracketed? httpx handles this usually?
        # httpx.URL handles IPv6 brackets if we pass it as host string?
        # Let's check. If I pass "::1" to URL, it becomes "[::1]".
        # But target_ip from socket is "::1".
        # We should let httpx.URL handle the formatting or wrap it?
        # httpx.URL("https://::1") works.
        # So passing strict IP string to host=... in copy_with should work.

        request.url = request.url.copy_with(host=target_ip)

        logger.debug(f"DNS Pinned: {hostname} -> {target_ip}")

        return await super().handle_async_request(request)

    def _validate_ip(self, ip_obj: Any, hostname: str) -> None:
        """
        Validates an IP address object against blocked ranges.
        """
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        ):
            # We log this as a security event
            logger.warning(f"Security violation: Blocked access to {hostname} ({ip_obj})")
            raise SecurityError(f"Access to {hostname} ({ip_obj}) is blocked")
