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
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from coreason_identity.config import CoreasonIdentityConfig


# Helper to format getaddrinfo response
def mock_addr_info_list(ips: list[str]) -> list[tuple[Any, Any, int, str, tuple[str, int]]]:
    results = []
    for ip in ips:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        results.append((family, socket.SOCK_STREAM, 6, "", (ip, 443)))
    return results


class TestSSRFEdgeCases:
    """
    Edge case tests for SSRF protection.

    NOTE: Config validation removed. These tests verify config works without checks.
    """

    def test_mixed_safe_and_unsafe_ips(self) -> None:
        """Test that config does not reject mixed IPs."""
        unsafe_mix = ["8.8.8.8", "127.0.0.1"]
        with patch("socket.getaddrinfo") as mock_dns:
            CoreasonIdentityConfig(domain="mixed.risk", audience="aud")
            mock_dns.assert_not_called()

    def test_ipv4_mapped_ipv6_localhost(self) -> None:
        """Test IPv4-mapped IPv6 localhost address (::ffff:127.0.0.1)."""
        ipv6_mapped = "::ffff:127.0.0.1"
        with patch("socket.getaddrinfo") as mock_dns:
            CoreasonIdentityConfig(domain="mapped.local", audience="aud")
            mock_dns.assert_not_called()

    def test_ipv6_link_local(self) -> None:
        """Test IPv6 link-local address (fe80::...)."""
        link_local = "fe80::1"
        with patch("socket.getaddrinfo") as mock_dns:
            CoreasonIdentityConfig(domain="link.local", audience="aud")
            mock_dns.assert_not_called()

    def test_boundary_long_domain_name(self) -> None:
        """Test very long domain name."""
        long_part = "a" * 63
        long_domain = f"{long_part}.{long_part}.{long_part}.com"

        with patch("socket.getaddrinfo") as mock_dns:
            config = CoreasonIdentityConfig(domain=long_domain, audience="aud")
            assert config.domain == long_domain
            mock_dns.assert_not_called()

    def test_idn_domain_handling(self) -> None:
        """Test Internationalized Domain Name (IDN) handling."""
        idn_domain = "münchen.de"

        with patch("socket.getaddrinfo") as mock_dns:
            config = CoreasonIdentityConfig(domain=idn_domain, audience="aud")
            assert "münchen.de" in config.domain or "xn--mnchen-3ya.de" in config.domain
            mock_dns.assert_not_called()

    def test_obfuscated_ip_if_resolved(self) -> None:
        """Test obfuscated IP resolution is ignored at config time."""
        hex_ip_domain = "0x7f000001"  # 127.0.0.1
        with patch("socket.getaddrinfo") as mock_dns:
            CoreasonIdentityConfig(domain=hex_ip_domain, audience="aud")
            mock_dns.assert_not_called()
