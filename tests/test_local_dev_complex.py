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
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from coreason_identity.config import CoreasonIdentityConfig


# Helper to mock DNS resolution for localhost
def mock_localhost_addr(
    host: str, *args: list[object], **kwargs: dict[str, object]
) -> list[tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str, int]]]:
    del args, kwargs  # Unused
    if "localhost" in host:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8080))]
    return []


class TestLocalDevComplex:
    """Test suite for validating the Local Development experience (unsafe modes)."""

    def test_local_dev_http_localhost_blocked_by_default(self) -> None:
        """
        By default, connecting to http://localhost should fail due to TWO reasons:
        1. SSRF check (resolves to 127.0.0.1)
        2. HTTPS check (http scheme)

        We need to verify that failing to enable EITHER flag blocks the config.
        """
        # Case 1: Enable NEITHER
        with patch("socket.getaddrinfo", side_effect=mock_localhost_addr):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(
                    domain="localhost:8080", audience="aud", http_timeout=5.0, issuer="http://localhost:8080"
                )
            # Could be SSRF or HTTPS error depending on validation order
            err = str(exc.value)
            assert "Security violation" in err or "HTTPS is required" in err

    def test_local_dev_http_localhost_ssrf_bypass_only(self) -> None:
        """
        Enable SSRF bypass (COREASON_DEV_UNSAFE_MODE=true) but NOT HTTPS bypass (unsafe_local_dev=False).
        Should fail due to HTTPS requirement.
        """
        with (
            patch.dict(os.environ, {"COREASON_DEV_UNSAFE_MODE": "true"}),
            patch("socket.getaddrinfo", side_effect=mock_localhost_addr),
        ):
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(
                    domain="localhost:8080",
                    audience="aud",
                    http_timeout=5.0,
                    issuer="http://localhost:8080",
                    unsafe_local_dev=False,
                )
            assert "HTTPS is required" in str(exc.value)

    def test_local_dev_success_all_flags_enabled(self) -> None:
        """
        Enable BOTH flags. Should succeed.
        This represents the correct "Local Dev" configuration.
        """
        with (
            patch.dict(os.environ, {"COREASON_DEV_UNSAFE_MODE": "true"}),
            patch("socket.getaddrinfo", side_effect=mock_localhost_addr),
        ):
            config = CoreasonIdentityConfig(
                domain="localhost:8080",
                audience="aud",
                http_timeout=5.0,
                issuer="http://localhost:8080",
                unsafe_local_dev=True,
            )
            assert config.domain == "localhost:8080"
            assert config.issuer == "http://localhost:8080"
            assert config.unsafe_local_dev is True

    def test_local_dev_https_localhost_ssrf_bypass_only(self) -> None:
        """
        If using HTTPS with localhost (e.g. self-signed certs), we only need SSRF bypass.
        unsafe_local_dev=False is acceptable because scheme is HTTPS.
        """
        with (
            patch.dict(os.environ, {"COREASON_DEV_UNSAFE_MODE": "true"}),
            patch("socket.getaddrinfo", side_effect=mock_localhost_addr),
        ):
            config = CoreasonIdentityConfig(
                domain="localhost:8443",
                audience="aud",
                http_timeout=5.0,
                issuer="https://localhost:8443",
                unsafe_local_dev=False,  # Default
            )
            assert config.issuer == "https://localhost:8443"
