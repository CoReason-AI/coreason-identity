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
    """Test suite for SSRF protection in CoreasonIdentityConfig."""

    def test_ssrf_localhost_ipv4(self) -> None:
        """Test that localhost (127.0.0.1) is rejected."""
        with patch("socket.getaddrinfo", return_value=mock_addr_info("127.0.0.1")):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="localhost", audience="aud")
            # We check for a generic message part, exact text depends on implementation
            assert "resolves to a prohibited IP" in str(exc.value) or "Security violation" in str(exc.value)

    def test_ssrf_aws_metadata(self) -> None:
        """Test that AWS metadata service (169.254.169.254) is rejected."""
        with patch("socket.getaddrinfo", return_value=mock_addr_info("169.254.169.254")):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="metadata.aws", audience="aud")
            assert "resolves to a prohibited IP" in str(exc.value)

    def test_ssrf_private_network_192(self) -> None:
        """Test that private network (192.168.x.x) is rejected."""
        with patch("socket.getaddrinfo", return_value=mock_addr_info("192.168.1.50")):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="internal.corp", audience="aud")
            assert "resolves to a prohibited IP" in str(exc.value)

    def test_ssrf_private_network_10(self) -> None:
        """Test that private network (10.x.x.x) is rejected."""
        with patch("socket.getaddrinfo", return_value=mock_addr_info("10.0.0.5")):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="database.internal", audience="aud")
            assert "resolves to a prohibited IP" in str(exc.value)

    def test_ssrf_ipv6_localhost(self) -> None:
        """Test that IPv6 localhost (::1) is rejected."""
        with patch("socket.getaddrinfo", return_value=mock_addr_info("::1")):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="ipv6.local", audience="aud")
            assert "resolves to a prohibited IP" in str(exc.value)

    def test_ssrf_valid_public_domain(self) -> None:
        """Test that a valid public domain (8.8.8.8) is accepted."""
        # 8.8.8.8 is Google DNS, safe
        with patch("socket.getaddrinfo", return_value=mock_addr_info("8.8.8.8")):
            config = CoreasonIdentityConfig(pii_salt="test-salt", domain="google.com", audience="aud")
            assert config.domain == "google.com"

    def test_ssrf_dns_failure(self) -> None:
        """Test that DNS resolution failure raises an error (Fail Closed)."""
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="nonexistent.domain", audience="aud")
            assert "Unable to resolve domain" in str(exc.value)

    def test_ssrf_bypass_mode(self) -> None:
        """Test that validation is bypassed when COREASON_DEV_UNSAFE_MODE is true."""
        with (
            patch.dict(os.environ, {"COREASON_DEV_UNSAFE_MODE": "true"}),
            patch("socket.getaddrinfo", return_value=mock_addr_info("127.0.0.1")),
        ):
            config = CoreasonIdentityConfig(pii_salt="test-salt", domain="localhost", audience="aud")
            assert config.domain == "localhost"

    def test_ssrf_bypass_mode_false_default(self) -> None:
        """Test that validation is NOT bypassed if env var is missing or false."""
        # Case 1: missing (already covered by other tests, but explicit check here)
        with (
            patch("socket.getaddrinfo", return_value=mock_addr_info("127.0.0.1")),
            pytest.raises(ValidationError),
        ):
            CoreasonIdentityConfig(pii_salt="test-salt", domain="localhost", audience="aud")

        # Case 2: false
        with (
            patch.dict(os.environ, {"COREASON_DEV_UNSAFE_MODE": "false"}),
            patch("socket.getaddrinfo", return_value=mock_addr_info("127.0.0.1")),
            pytest.raises(ValidationError),
        ):
            CoreasonIdentityConfig(pii_salt="test-salt", domain="localhost", audience="aud")

    def test_ssrf_invalid_ip_format(self) -> None:
        """Test that invalid IP formats returned by DNS are ignored (robustness)."""
        # Return an invalid IP string to trigger ValueError in ipaddress.ip_address
        bad_response = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("NOT_AN_IP", 443))]
        with patch("socket.getaddrinfo", return_value=bad_response):
            # Should pass because it ignores the invalid IP and finds no other unsafe IPs
            config = CoreasonIdentityConfig(pii_salt="test-salt", domain="example.com", audience="aud")
            assert config.domain == "example.com"
