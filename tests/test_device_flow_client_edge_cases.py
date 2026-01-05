# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from typing import Generator
from unittest.mock import Mock, patch

import pytest
from httpx import Request, Response

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError


@pytest.fixture  # type: ignore[misc]
def client() -> DeviceFlowClient:
    return DeviceFlowClient(client_id="test-client", idp_url="https://test.auth0.com")


@pytest.fixture  # type: ignore[misc]
def mock_httpx() -> Generator[Mock, None, None]:
    with patch("httpx.Client") as mock:
        yield mock


def create_response(status_code: int, content: bytes) -> Response:
    request = Request("GET", "https://example.com")
    return Response(status_code, content=content, request=request)


def test_discovery_returns_invalid_json(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test that non-JSON response from OIDC discovery raises CoreasonIdentityError."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, content=b"<html>Error</html>")

    with pytest.raises(CoreasonIdentityError, match="Invalid JSON response from OIDC discovery"):
        client._get_endpoints()


def test_initiate_flow_returns_invalid_json(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test that non-JSON response from initiate_flow raises CoreasonIdentityError."""
    mock_instance = mock_httpx.return_value.__enter__.return_value

    # Mock discovery success
    mock_instance.get.return_value = Response(
        200,
        json={
            "device_authorization_endpoint": "https://idp/device",
            "token_endpoint": "https://idp/token",
        },
        request=Request("GET", "url"),
    )

    # Mock initiate flow failure (200 OK but HTML)
    mock_instance.post.return_value = create_response(200, content=b"<html>Error</html>")

    with pytest.raises(CoreasonIdentityError, match="Invalid JSON response from initiate flow"):
        client.initiate_flow()
