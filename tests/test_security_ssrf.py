# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import os
import socket
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from coreason_identity.config import CoreasonIdentityConfig


# Helper to format getaddrinfo response
def mock_addr_info(ip: str) -> list[tuple[Any, Any, int, str, tuple[str, int]]]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", (ip, 443))]


class TestSSRFProtection:
    """
    Test suite for SSRF protection in CoreasonIdentityConfig.

    NOTE: Validation logic has been moved to connection time (SafeHTTPTransport).
    These tests now verify that CoreasonIdentityConfig does NOT perform DNS resolution,
    preventing TOCTOU vulnerabilities and startup issues.
    """

    def test_ssrf_localhost_ipv4(self) -> None:
        """Test that localhost (127.0.0.1) is NOT rejected by config (moved to transport)."""
        with patch("socket.getaddrinfo") as mock_dns:
            config = CoreasonIdentityConfig(domain="localhost", audience="aud")
            assert config.domain == "localhost"
            # Verify no DNS resolution happens at config time
            mock_dns.assert_not_called()

    def test_ssrf_aws_metadata(self) -> None:
        """Test that AWS metadata service is NOT rejected by config."""
        with patch("socket.getaddrinfo") as mock_dns:
            CoreasonIdentityConfig(domain="metadata.aws", audience="aud")
            mock_dns.assert_not_called()

    def test_ssrf_private_network_192(self) -> None:
        """Test that private network (192.168.x.x) is NOT rejected by config."""
        with patch("socket.getaddrinfo") as mock_dns:
            CoreasonIdentityConfig(domain="internal.corp", audience="aud")
            mock_dns.assert_not_called()

    def test_ssrf_private_network_10(self) -> None:
        """Test that private network (10.x.x.x) is NOT rejected by config."""
        with patch("socket.getaddrinfo") as mock_dns:
            CoreasonIdentityConfig(domain="database.internal", audience="aud")
            mock_dns.assert_not_called()

    def test_ssrf_ipv6_localhost(self) -> None:
        """Test that IPv6 localhost (::1) is NOT rejected by config."""
        with patch("socket.getaddrinfo") as mock_dns:
            CoreasonIdentityConfig(domain="ipv6.local", audience="aud")
            mock_dns.assert_not_called()

    def test_ssrf_valid_public_domain(self) -> None:
        """Test that a valid public domain is accepted."""
        with patch("socket.getaddrinfo") as mock_dns:
            config = CoreasonIdentityConfig(domain="google.com", audience="aud")
            assert config.domain == "google.com"
            mock_dns.assert_not_called()

    def test_ssrf_dns_failure(self) -> None:
        """Test that DNS resolution failure does NOT raise an error at config time."""
        with patch("socket.getaddrinfo") as mock_dns:
            config = CoreasonIdentityConfig(domain="nonexistent.domain", audience="aud")
            assert config.domain == "nonexistent.domain"
            mock_dns.assert_not_called()

    def test_ssrf_bypass_mode(self) -> None:
        """Test that validation bypass logic is removed/irrelevant for config."""
        # This test is now less relevant but ensures no error regardless of env var
        with (
            patch.dict(os.environ, {"COREASON_DEV_UNSAFE_MODE": "true"}),
            patch("socket.getaddrinfo") as mock_dns,
        ):
            config = CoreasonIdentityConfig(domain="localhost", audience="aud")
            assert config.domain == "localhost"
            mock_dns.assert_not_called()

    def test_ssrf_bypass_mode_false_default(self) -> None:
        """Test that validation bypass logic is irrelevant."""
        with (
            patch("socket.getaddrinfo") as mock_dns,
        ):
            config = CoreasonIdentityConfig(domain="localhost", audience="aud")
            assert config.domain == "localhost"
            mock_dns.assert_not_called()

    def test_ssrf_invalid_ip_format(self) -> None:
        """Test that invalid IP formats are irrelevant since we don't resolve."""
        with patch("socket.getaddrinfo") as mock_dns:
            config = CoreasonIdentityConfig(domain="example.com", audience="aud")
            assert config.domain == "example.com"
            mock_dns.assert_not_called()
