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
    """Edge case tests for SSRF protection."""

    def test_mixed_safe_and_unsafe_ips(self) -> None:
        """Test that if ANY resolved IP is unsafe, validation fails."""
        # Domain resolves to 8.8.8.8 (Safe) AND 127.0.0.1 (Unsafe)
        # This simulates DNS rebinding preparation or misconfiguration
        unsafe_mix = ["8.8.8.8", "127.0.0.1"]
        with patch("socket.getaddrinfo", return_value=mock_addr_info_list(unsafe_mix)):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="mixed.risk", audience="aud")
            assert "resolves to a prohibited IP" in str(exc.value)

    def test_ipv4_mapped_ipv6_localhost(self) -> None:
        """Test IPv4-mapped IPv6 localhost address (::ffff:127.0.0.1)."""
        # ::ffff:7f00:1 is ::ffff:127.0.0.1
        ipv6_mapped = "::ffff:127.0.0.1"
        with patch("socket.getaddrinfo", return_value=mock_addr_info_list([ipv6_mapped])):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="mapped.local", audience="aud")
            assert "resolves to a prohibited IP" in str(exc.value)

    def test_ipv6_link_local(self) -> None:
        """Test IPv6 link-local address (fe80::...)."""
        link_local = "fe80::1"
        with patch("socket.getaddrinfo", return_value=mock_addr_info_list([link_local])):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="link.local", audience="aud")
            assert "resolves to a prohibited IP" in str(exc.value)

    def test_boundary_long_domain_name(self) -> None:
        """Test very long domain name (253 chars) does not crash logic if resolved."""
        # 63 chars * 4 segments = 252 + dots = ~255
        long_part = "a" * 63
        long_domain = f"{long_part}.{long_part}.{long_part}.com"

        # If it resolves to a safe IP, it should pass
        with patch("socket.getaddrinfo", return_value=mock_addr_info_list(["8.8.8.8"])):
            config = CoreasonIdentityConfig(pii_salt="test-salt", domain=long_domain, audience="aud")
            assert config.domain == long_domain

    def test_idn_domain_handling(self) -> None:
        """Test Internationalized Domain Name (IDN) handling."""
        # "münchen.de" -> xn--mnchen-3ya.de
        # pydantic/urlparse might punycode it, or keep it utf-8.
        # Crucially, getaddrinfo must handle it.
        # We mock getaddrinfo receiving the normalized version or the original.
        idn_domain = "münchen.de"

        # We simulate that the system resolves this IDN to a safe IP
        with patch("socket.getaddrinfo", return_value=mock_addr_info_list(["1.1.1.1"])):
            config = CoreasonIdentityConfig(pii_salt="test-salt", domain=idn_domain, audience="aud")
            # The validator returns the normalized domain.
            # Our normalize_domain lowercases.
            # Note: urlparse.netloc behavior on IDNs varies by python version/install,
            # but usually keeps unicode in recent versions unless encoded.
            assert "münchen.de" in config.domain or "xn--mnchen-3ya.de" in config.domain

    def test_obfuscated_ip_if_resolved(self) -> None:
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
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain=hex_ip_domain, audience="aud")
            assert "resolves to a prohibited IP" in str(exc.value)
