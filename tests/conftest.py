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
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_dns_resolution() -> Generator[MagicMock, None, None]:
    """
    Globally patches socket.getaddrinfo to return a safe public IP by default.
    This prevents SSRF validation logic in CoreasonIdentityConfig from failing
    existing tests that use dummy domains (e.g., test.auth0.com).

    Tests that need to verify SSRF logic (like test_security_ssrf.py) should
    explicitly patch socket.getaddrinfo again or configure this mock's return value.
    """
    # Default safe response: 8.8.8.8 (Google DNS)
    # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
    safe_response = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    with patch("socket.getaddrinfo", return_value=safe_response) as mock:
        yield mock
