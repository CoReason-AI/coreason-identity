# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import Mock, patch, AsyncMock
import pytest
import httpx
from coreason_identity.manager import IdentityManagerAsync
from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.models import DeviceFlowResponse, TokenResponse

@pytest.fixture
def config():
    return CoreasonIdentityConfig(domain="test.com", audience="aud", client_id="cid")

@pytest.mark.asyncio
async def test_manager_async_lifecycle(config):
    # Test internal client creation and cleanup
    mgr = IdentityManagerAsync(config)
    assert mgr._internal_client is True
    assert mgr._client is not None

    with patch.object(mgr._client, "aclose", new_callable=AsyncMock) as mock_close:
        await mgr.__aenter__()

        # Check if children entered
        # We can't easily check children state without mocking them or checking their internals
        # But we can assume if no error, it's fine.

        await mgr.__aexit__(None, None, None)
        mock_close.assert_awaited_once()

@pytest.mark.asyncio
async def test_manager_async_external_client(config):
    client = AsyncMock(spec=httpx.AsyncClient)
    client.is_closed = False
    mgr = IdentityManagerAsync(config, client=client)
    assert mgr._internal_client is False
    assert mgr.oidc_provider._client is client

    await mgr.__aenter__()
    await mgr.__aexit__(None, None, None)

    # Should not close external client
    client.aclose.assert_not_called()

@pytest.mark.asyncio
async def test_manager_async_device_flow(config):
    mgr = IdentityManagerAsync(config)
    mock_df_client = AsyncMock()

    # We mock the class so we can capture the instance
    with patch("coreason_identity.manager.DeviceFlowClientAsync", return_value=mock_df_client):
        # We also need to mock __aenter__ to return self
        mock_df_client.__aenter__.return_value = mock_df_client

        await mgr.__aenter__()

        # start_device_login
        mock_df_client.initiate_flow.return_value = DeviceFlowResponse(
             device_code="dc", user_code="uc", verification_uri="uri", expires_in=300, interval=5
        )
        resp = await mgr.start_device_login()
        assert resp.device_code == "dc"

        # Check client passed
        assert mgr.device_client is mock_df_client

        # await_device_token
        mock_df_client.poll_token.return_value = TokenResponse(
             access_token="at", token_type="Bearer", expires_in=3600
        )
        token = await mgr.await_device_token(resp)
        assert token.access_token == "at"

        await mgr.__aexit__(None, None, None)
