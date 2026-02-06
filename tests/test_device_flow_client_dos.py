from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import DeviceFlowResponse


@pytest.mark.asyncio
async def test_poll_token_enforces_minimum_interval() -> None:
    """Test that poll_token enforces the minimum polling interval."""
    # Setup
    client_mock = AsyncMock(spec=httpx.AsyncClient)

    # Mock discovery endpoint
    discovery_resp = MagicMock()
    discovery_resp.status_code = 200
    discovery_resp.json.return_value = {
        "token_endpoint": "https://idp.example.com/oauth/token",
        "device_authorization_endpoint": "https://idp.example.com/oauth/device/code",
        "issuer": "https://idp",
        "jwks_uri": "https://idp/jwks",
    }
    client_mock.get.return_value = discovery_resp

    # First response: authorization_pending
    pending_resp = MagicMock()
    pending_resp.status_code = 400
    pending_resp.json.return_value = {"error": "authorization_pending"}

    # Second response: Success
    success_resp = MagicMock()
    success_resp.status_code = 200
    success_resp.json.return_value = {"access_token": "valid_token", "token_type": "Bearer", "expires_in": 3600}

    client_mock.post.side_effect = [pending_resp, success_resp]

    # Initialize client with default min_poll_interval=5.0
    df_client = DeviceFlowClient(
        client_id="test-client", idp_url="https://idp.example.com", client=client_mock, min_poll_interval=5.0
    )

    # Mock initiate_flow result with UNSAFE interval 0
    device_resp = DeviceFlowResponse(
        device_code="device-code",
        user_code="user-code",
        verification_uri="https://verify.com",
        expires_in=300,
        interval=0,
    )

    with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
        token = await df_client.poll_token(device_resp)

        # Verify result
        assert token.access_token == "valid_token"

        # Verify sleep was called with min_poll_interval (5.0), not 0
        # It should be called once before the second attempt
        assert mock_sleep.call_count == 1
        mock_sleep.assert_called_with(5.0)


@pytest.mark.asyncio
async def test_poll_token_enforces_max_duration() -> None:
    """Test that poll_token raises CoreasonIdentityError when max polling duration is exceeded."""
    # Setup
    client_mock = AsyncMock(spec=httpx.AsyncClient)

    # Mock discovery endpoint
    discovery_resp = MagicMock()
    discovery_resp.status_code = 200
    discovery_resp.json.return_value = {
        "token_endpoint": "https://idp.example.com/oauth/token",
        "device_authorization_endpoint": "https://idp.example.com/oauth/device/code",
        "issuer": "https://idp",
        "jwks_uri": "https://idp/jwks",
    }
    client_mock.get.return_value = discovery_resp

    # Always pending
    pending_resp = MagicMock()
    pending_resp.status_code = 400
    pending_resp.json.return_value = {"error": "authorization_pending"}
    client_mock.post.return_value = pending_resp

    df_client = DeviceFlowClient(
        client_id="test-client",
        idp_url="https://idp.example.com",
        client=client_mock,
        max_poll_duration=10.0,  # Short duration
    )

    device_resp = DeviceFlowResponse(
        device_code="device-code",
        user_code="user-code",
        verification_uri="https://verify.com",
        expires_in=10000,  # Long expiration
        interval=1,
    )

    # Mock time.time to simulate timeout
    start_time_val = 1000.0

    with patch("time.time") as mock_time:
        # Side effect returns values for each call
        # 1. start_time = time.time()
        # 2. Loop condition check 1: time.time() < min(...) (True)
        # 3. Loop condition check 2: time.time() < min(...) (False)
        # 4. Safety check: time.time() >= safety_end_time (True)
        mock_time.side_effect = [
            start_time_val,  # 1. start_time assignment
            start_time_val,  # 2. First loop condition check (True)
            start_time_val + 11.0,  # 3. Second loop condition check (False, 11 > 10)
            start_time_val + 11.0,  # 4. Safety check (True, 11 >= 10)
        ]

        with patch("anyio.sleep", new_callable=AsyncMock):
            with pytest.raises(CoreasonIdentityError) as excinfo:
                await df_client.poll_token(device_resp)

            assert "Polling timed out (safety limit reached)." in str(excinfo.value)
