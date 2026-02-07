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
    """Complex workflow tests for SSRF protection."""

    def test_environment_toggling_workflow(self) -> None:
        """
        Verify that the validation logic correctly respects the environment variable
        changing dynamically (simulating config reloads or environment shifts in tests).
        """
        unsafe_domain = "localhost"
        safe_ip_mock = mock_addr_info("127.0.0.1")  # Real resolution of localhost is unsafe

        with patch("socket.getaddrinfo", return_value=safe_ip_mock):
            # 1. Start Secure (Default) -> Should Fail
            with pytest.raises(ValidationError):
                CoreasonIdentityConfig(pii_salt="test-salt", domain=unsafe_domain, audience="aud")

            # 2. Enable Unsafe Mode -> Should Pass
            with patch.dict(os.environ, {"COREASON_DEV_UNSAFE_MODE": "true"}):
                cfg = CoreasonIdentityConfig(pii_salt="test-salt", domain=unsafe_domain, audience="aud")
                assert cfg.domain == unsafe_domain

            # 3. Disable Unsafe Mode (Explicit False) -> Should Fail
            with (
                patch.dict(os.environ, {"COREASON_DEV_UNSAFE_MODE": "false"}),
                pytest.raises(ValidationError),
            ):
                CoreasonIdentityConfig(pii_salt="test-salt", domain=unsafe_domain, audience="aud")

    def test_dns_flake_then_success_fail_closed(self) -> None:
        """
        Simulate a flaky DNS resolver that first raises an error, then resolves to an unsafe IP.
        This verifies that we fail closed on the first error and don't accidentally pass
        if retries were implemented (which they aren't, but this ensures robust behavior).
        """
        with patch("socket.getaddrinfo") as mock_dns:
            # First call raises error
            mock_dns.side_effect = [socket.gaierror("Temporary failure"), mock_addr_info("127.0.0.1")]

            # Attempt 1: Should fail due to DNS error
            with pytest.raises(ValidationError) as exc1:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="flaky.local", audience="aud")
            assert "Unable to resolve" in str(exc1.value)

            # Fix side effect for next call (simulate retry logic in a consumer)
            mock_dns.side_effect = None
            mock_dns.return_value = mock_addr_info("127.0.0.1")

            # Attempt 2: Should fail due to Unsafe IP
            with pytest.raises(ValidationError) as exc2:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="flaky.local", audience="aud")
            assert "resolves to a prohibited IP" in str(exc2.value)

    def test_recursive_cname_chain_resolution(self) -> None:
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
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(pii_salt="test-salt", domain="public.alias.to.internal", audience="aud")
            assert "resolves to a prohibited IP" in str(exc.value)
