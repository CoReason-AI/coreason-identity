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
from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import DeviceFlowResponse, TokenResponse
from httpx import Request, Response


@pytest.fixture
def client() -> DeviceFlowClient:
    return DeviceFlowClient(client_id="test-client", idp_url="https://test.auth0.com")


@pytest.fixture
def mock_httpx() -> Generator[Mock, None, None]:
    with patch("httpx.Client") as mock:
        yield mock


def create_response(status_code: int, json_data: Optional[Any] = None, content: Optional[bytes] = None) -> Response:
    request = Request("GET", "https://example.com")
    if json_data is not None:
        return Response(status_code, json=json_data, request=request)
    return Response(status_code, content=content, request=request)


def test_get_endpoints_success(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(
        200,
        {
            "device_authorization_endpoint": "https://test.auth0.com/oauth/device/code",
            "token_endpoint": "https://test.auth0.com/oauth/token",
        },
    )

    endpoints = client._get_endpoints()
    assert endpoints["device_authorization_endpoint"] == "https://test.auth0.com/oauth/device/code"
    assert endpoints["token_endpoint"] == "https://test.auth0.com/oauth/token"
    mock_instance.get.assert_called_once_with("https://test.auth0.com/.well-known/openid-configuration")

    # Test Caching
    endpoints2 = client._get_endpoints()
    assert endpoints2 is endpoints
    assert mock_instance.get.call_count == 1


def test_get_endpoints_fallback(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test fallback when specific keys are missing in config."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {})  # Empty config

    endpoints = client._get_endpoints()
    assert endpoints["device_authorization_endpoint"] == "https://test.auth0.com/oauth/device/code"
    assert endpoints["token_endpoint"] == "https://test.auth0.com/oauth/token"


def test_get_endpoints_failure(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(500, "Internal Server Error")

    with pytest.raises(CoreasonIdentityError, match="Failed to discover OIDC endpoints"):
        client._get_endpoints()


def test_initiate_flow_success(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    mock_instance = mock_httpx.return_value.__enter__.return_value

    # Mock discovery
    mock_instance.get.return_value = create_response(
        200,
        {
            "device_authorization_endpoint": "https://test.auth0.com/device",
            "token_endpoint": "https://test.auth0.com/token",
        },
    )

    # Mock initiation
    mock_instance.post.return_value = create_response(
        200,
        {
            "device_code": "dc_123",
            "user_code": "uc_123",
            "verification_uri": "https://verify.com",
            "expires_in": 300,
            "interval": 5,
        },
    )

    resp = client.initiate_flow(audience="api://test")

    assert isinstance(resp, DeviceFlowResponse)
    assert resp.device_code == "dc_123"
    assert resp.user_code == "uc_123"

    # Verify post args
    mock_instance.post.assert_called_once()
    args, kwargs = mock_instance.post.call_args
    assert args[0] == "https://test.auth0.com/device"
    assert kwargs["data"]["audience"] == "api://test"


def test_initiate_flow_http_error(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {})
    mock_instance.post.return_value = create_response(500, "Error")

    with pytest.raises(CoreasonIdentityError, match="Failed to initiate device flow"):
        client.initiate_flow()


def test_initiate_flow_validation_error(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {})
    mock_instance.post.return_value = create_response(200, {})  # Missing fields

    with pytest.raises(CoreasonIdentityError, match="Invalid response from IdP"):
        client.initiate_flow()


def test_poll_token_success(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    mock_instance = mock_httpx.return_value.__enter__.return_value

    # Discovery
    mock_instance.get.return_value = create_response(
        200,
        {
            "token_endpoint": "https://test.auth0.com/token",
        },
    )

    # Polling responses: pending -> success
    mock_instance.post.side_effect = [
        create_response(400, {"error": "authorization_pending"}),
        create_response(200, {"access_token": "at_123", "token_type": "Bearer", "expires_in": 3600}),
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("time.sleep") as mock_sleep:
        token_resp = client.poll_token(device_resp)

    assert isinstance(token_resp, TokenResponse)
    assert token_resp.access_token == "at_123"
    assert mock_instance.post.call_count == 2
    mock_sleep.assert_called_once_with(1)


def test_poll_token_slow_down(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # slow_down -> success
    mock_instance.post.side_effect = [
        create_response(400, {"error": "slow_down"}),
        create_response(200, {"access_token": "at", "token_type": "Bearer", "expires_in": 3600}),
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("time.sleep") as mock_sleep:
        client.poll_token(device_resp)
        mock_sleep.assert_called_once_with(6)


def test_poll_token_access_denied(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    mock_instance.post.return_value = create_response(400, {"error": "access_denied"})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="User denied access"):
        with patch("time.sleep"):
            client.poll_token(device_resp)


def test_poll_token_expired_token(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    mock_instance.post.return_value = create_response(400, {"error": "expired_token"})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Device code expired"):
        with patch("time.sleep"):
            client.poll_token(device_resp)


def test_poll_token_timeout(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})
    mock_instance.post.return_value = create_response(400, {"error": "authorization_pending"})

    # Set expires_in to 1 second
    device_resp = DeviceFlowResponse(device_code="dc", user_code="uc", verification_uri="url", expires_in=1, interval=1)

    with patch("time.time") as mock_time, patch("time.sleep"):
        mock_time.side_effect = [0, 0, 2]

        with pytest.raises(CoreasonIdentityError, match="Polling timed out"):
            client.poll_token(device_resp)


def test_poll_token_unexpected_error(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test when polling receives a 500 error."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 500 error - httpx.Response(500, json={"error": "server error"})
    # This should trigger response.raise_for_status() in the 'else' block or catch block
    mock_instance.post.return_value = create_response(500, {"error": "server_error"})

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Polling failed"):
        with patch("time.sleep"):
            client.poll_token(device_resp)


def test_poll_token_invalid_json_type(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test when polling receives a valid JSON that isn't a dict (e.g. list)."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 400 but returns a list?
    mock_instance.post.return_value = create_response(400, ["error"])

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Received invalid JSON response"):
        with patch("time.sleep"):
            client.poll_token(device_resp)


def test_poll_token_non_json_500(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test when polling receives non-JSON content with 500 error."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 500 with text
    mock_instance.post.return_value = create_response(500, content=b"Server Error")

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Polling failed"):
        with patch("time.sleep"):
            client.poll_token(device_resp)


def test_poll_token_non_json_200(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test when polling receives non-JSON content with 200 OK (Unexpected)."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 200 with text - response.json() fails
    mock_instance.post.return_value = create_response(200, content=b"Not JSON")

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Received invalid JSON response on 200 OK"):
        with patch("time.sleep"):
            client.poll_token(device_resp)


def test_poll_token_204_empty(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test when polling receives 204 No Content (should trigger generic error)."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # 204 No Content
    mock_instance.post.return_value = create_response(204)

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with pytest.raises(CoreasonIdentityError, match="Received invalid response"):
        with patch("time.sleep"):
            client.poll_token(device_resp)


def test_poll_token_generic_exception_retry(client: DeviceFlowClient, mock_httpx: Mock) -> None:
    """Test retry logic on generic exception."""
    mock_instance = mock_httpx.return_value.__enter__.return_value
    mock_instance.get.return_value = create_response(200, {"token_endpoint": "url"})

    # Fail once with network error, then succeed
    mock_instance.post.side_effect = [
        Exception("Network Error"),
        create_response(200, {"access_token": "at_123", "token_type": "Bearer", "expires_in": 3600}),
    ]

    device_resp = DeviceFlowResponse(
        device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
    )

    with patch("time.sleep") as mock_sleep:
        token_resp = client.poll_token(device_resp)

    assert isinstance(token_resp, TokenResponse)
    assert token_resp.access_token == "at_123"
    assert mock_instance.post.call_count == 2
    mock_sleep.assert_called_once_with(1)
