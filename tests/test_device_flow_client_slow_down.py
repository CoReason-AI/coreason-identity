# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import Mock, patch

import pytest
from httpx import Response

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.models import DeviceFlowResponse, TokenResponse


class TestDeviceFlowClientSlowDown:
    @pytest.fixture
    def client(self) -> DeviceFlowClient:
        # Pre-populate endpoints to skip discovery
        c = DeviceFlowClient("client-id", "https://idp")
        c._endpoints = {
            "device_authorization_endpoint": "https://idp/device",
            "token_endpoint": "https://idp/token",
        }
        return c

    @patch("time.sleep")
    @patch("httpx.Client")
    def test_slow_down_increases_interval(self, mock_httpx: Mock, mock_sleep: Mock, client: DeviceFlowClient) -> None:
        """
        Test that receiving 'slow_down' increases the polling interval by 5 seconds.
        """
        mock_http_client = mock_httpx.return_value.__enter__.return_value

        # Setup responses:
        # 1. slow_down
        # 2. success

        response_slow_down = Response(400, json={"error": "slow_down"})
        response_success = Response(200, json={"access_token": "at", "token_type": "Bearer", "expires_in": 3600})

        mock_http_client.post.side_effect = [response_slow_down, response_success]

        flow = DeviceFlowResponse(
            device_code="dcode",
            user_code="ucode",
            verification_uri="uri",
            expires_in=60,
            interval=5,  # Initial interval
        )

        token = client.poll_token(flow)

        assert isinstance(token, TokenResponse)
        assert token.access_token == "at"

        # Verify sleep calls
        # Sleep is called after the first request (which returns slow_down).
        # Logic:
        # 1. Request -> slow_down.
        # 2. interval = 5 + 5 = 10.
        # 3. time.sleep(10).
        # 4. Request -> success.
        # 5. Returns (no sleep).

        assert mock_sleep.call_count == 1

        # Check arguments
        mock_sleep.assert_called_with(10)
