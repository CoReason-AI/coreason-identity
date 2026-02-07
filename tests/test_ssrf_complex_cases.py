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


class TestSSRFComplexCases:
    """
    Complex workflow tests for SSRF protection.

    NOTE: Validation moved to transport layer. Config validation is removed.
    These tests now verify that config initialization succeeds without DNS resolution.
    """

    def test_environment_toggling_workflow(self) -> None:
        """
        Verify that config initialization succeeds regardless of environment variables
        since DNS validation is moved to connection time.
        """
        unsafe_domain = "localhost"

        with patch("socket.getaddrinfo") as mock_dns:
            # 1. Start Secure (Default) -> Should Pass (no check)
            CoreasonIdentityConfig(domain=unsafe_domain, audience="aud")
            mock_dns.assert_not_called()

            # 2. Enable Unsafe Mode -> Should Pass
            with patch.dict(os.environ, {"COREASON_DEV_UNSAFE_MODE": "true"}):
                cfg = CoreasonIdentityConfig(domain=unsafe_domain, audience="aud")
                assert cfg.domain == unsafe_domain
                mock_dns.assert_not_called()

            # 3. Disable Unsafe Mode (Explicit False) -> Should Pass
            with patch.dict(os.environ, {"COREASON_DEV_UNSAFE_MODE": "false"}):
                CoreasonIdentityConfig(domain=unsafe_domain, audience="aud")
                mock_dns.assert_not_called()

    def test_dns_flake_then_success_fail_closed(self) -> None:
        """
        Simulate a flaky DNS resolver. Config should succeed as it doesn't resolve DNS.
        """
        with patch("socket.getaddrinfo") as mock_dns:
            # Config init should not call DNS, so side_effect is irrelevant if not called
            mock_dns.side_effect = [socket.gaierror("Temporary failure"), mock_addr_info("127.0.0.1")]

            # Should succeed
            CoreasonIdentityConfig(domain="flaky.local", audience="aud")
            mock_dns.assert_not_called()

    def test_recursive_cname_chain_resolution(self) -> None:
        """
        Test that config ignores recursive DNS resolution logic.
        """
        # Scenario: public.cname -> internal.cname -> 192.168.1.1
        final_resolution = mock_addr_info("192.168.1.1")

        with patch("socket.getaddrinfo", return_value=final_resolution) as mock_dns:
            CoreasonIdentityConfig(domain="public.alias.to.internal", audience="aud")
            mock_dns.assert_not_called()
