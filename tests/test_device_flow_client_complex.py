# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from typing import Any, Generator, Optional
from unittest.mock import Mock, patch

import pytest
from httpx import Request, Response

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import DeviceFlowResponse


@pytest.fixture  # type: ignore[misc]
def client() -> DeviceFlowClient:
    return DeviceFlowClient(client_id="test-client", idp_url="https://test.auth0.com")


@pytest.fixture  # type: ignore[misc]
def mock_httpx() -> Generator[Mock, None, None]:
    with patch("httpx.Client") as mock:
        yield mock


def create_response(status_code: int, json_data: Optional[Any] = None, content: Optional[bytes] = None) -> Response:
    request = Request("GET", "https://example.com")
    if json_data is not None:
        return Response(status_code, json=json_data, request=request)
    return Response(status_code, content=content, request=request)


def test_poll_token_flaky_network(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test polling where requests fail intermittently (network error) but eventually succeed."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # Fail, Pending, Fail, Success
    mock_instance.post.side_effect = [
        Exception("Network glitch 1"),
        create_response(400, {"error": "authorization_pending"}),
        Exception("Network glitch 2"),
        create_response(200, {"access_token": "at", "token_type": "B", "expires_in": 3600}),
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("time.sleep") as mock_sleep:
        token_resp = client.poll_token(device_resp)
        # Should succeed
        assert token_resp.access_token == "at"
        # Total 4 calls
        assert mock_instance.post.call_count == 4
        # Sleep called 3 times (after each non-success)
        assert mock_sleep.call_count == 3


def test_poll_token_compounding_slow_down(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test multiple slow_down responses increasing the interval."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # slow_down, slow_down, success
    mock_instance.post.side_effect = [
        create_response(400, {"error": "slow_down"}),
        create_response(400, {"error": "slow_down"}),
        create_response(200, {"access_token": "at", "token_type": "B", "expires_in": 3600}),
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=20, interval=5
    )

    with patch("time.sleep") as mock_sleep:
        client.poll_token(device_resp)

        # Initial interval: 5
        # 1st slow_down: interval -> 5+5=10. sleep(10).
        # 2nd slow_down: interval -> 10+5=15. sleep(15).
        # Success.

        assert mock_sleep.call_args_list == [
            ((10,),),
            ((15,),),
        ]


def test_poll_token_malformed_success(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test 200 OK but missing required fields (access_token)."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 200 OK but missing 'access_token'
    mock_instance.post.return_value = create_response(200, {"foo": "bar", "expires_in": 3600})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Received invalid token response structure"):
        with patch("time.sleep"):
            client.poll_token(device_resp)


def test_poll_token_legacy_error_in_200(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test 200 OK containing an error field (legacy behavior)."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 200 OK with error payload
    mock_instance.post.return_value = create_response(200, {"error": "access_denied", "error_description": "Legacy"})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    # Should raise ValidationError because access_token is missing, caught and re-raised as CoreasonIdentityError
    with pytest.raises(CoreasonIdentityError, match="Received invalid token response structure"):
        with patch("time.sleep"):
            client.poll_token(device_resp)


def test_discovery_complex_failure(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test discovery returns corrupted JSON, fallback logic."""
    mock_instance = mock_httpx.return_value.__enter__.return_value

    # Discovery returns invalid JSON
    mock_instance.get.return_value = create_response(200, content=b"{invalid_json}")

    # The code expects valid JSON. If json() fails, it raises JSONDecodeError -> ValueError?
    # No, _get_endpoints calls response.json(). If it fails, it raises.
    # It is not wrapped in specific try/except in _get_endpoints, so it propagates?
    # Or HTTPError? No.
    # Let's check _get_endpoints implementation.
    # It has try/except httpx.HTTPError. But json() raising ValueError is not HTTPError.

    with pytest.raises(ValueError):  # Or whatever json() raises
        client._get_endpoints()
