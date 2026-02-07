# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from coreason_identity.config import CoreasonClientConfig
from coreason_identity.manager import IdentityManager, IdentityManagerAsync
from coreason_identity.models import DeviceFlowResponse, TokenResponse, UserContext


def test_sync_facade_context_manager() -> None:
    config = CoreasonClientConfig(domain="test.auth0.com", audience="aud", client_id="cid")

    with patch("coreason_identity.manager.IdentityManagerAsync") as MockAsync:
        mock_instance = MockAsync.return_value
        mock_instance.__aexit__ = AsyncMock()

        with IdentityManager(config) as mgr:
            assert mgr._async == mock_instance

        mock_instance.__aexit__.assert_called_once()


def test_sync_facade_methods() -> None:
    config = CoreasonClientConfig(domain="test.auth0.com", audience="aud", client_id="cid")

    with patch("coreason_identity.manager.IdentityManagerAsync") as MockAsync:
        mock_instance = MockAsync.return_value

        # Setup specific return types to satisfy mypy strict checks
        mock_context = Mock(spec=UserContext)
        mock_flow = Mock(spec=DeviceFlowResponse)
        mock_token = Mock(spec=TokenResponse)

        mock_instance.validate_token = AsyncMock(return_value=mock_context)
        mock_instance.start_device_login = AsyncMock(return_value=mock_flow)
        mock_instance.await_device_token = AsyncMock(return_value=mock_token)

        mgr = IdentityManager(config)

        # Test validate_token
        res = mgr.validate_token("header")
        assert res == mock_context
        mock_instance.validate_token.assert_called_with("header")

        # Test start_device_login
        res_flow = mgr.start_device_login(scope="scope")
        assert res_flow == mock_flow
        mock_instance.start_device_login.assert_called_with("scope")

        # Test await_device_token
        flow_input = DeviceFlowResponse(device_code="d", user_code="u", verification_uri="v", expires_in=1, interval=1)
        res_token = mgr.await_device_token(flow_input)
        assert res_token == mock_token
        mock_instance.await_device_token.assert_called_with(flow_input)


@pytest.mark.asyncio
async def test_async_manager_internal_client_cleanup() -> None:
    """Test that IdentityManagerAsync closes the internal client on exit."""
    config = CoreasonClientConfig(domain="test.auth0.com", audience="aud", client_id="cid")

    # Mock httpx.AsyncClient to track aclose
    with patch("httpx.AsyncClient") as MockClient:
        mock_client_instance = MockClient.return_value
        mock_client_instance.aclose = AsyncMock()

        async with IdentityManagerAsync(config) as mgr:
            assert mgr._internal_client is True
            assert mgr._client == mock_client_instance

        mock_client_instance.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_manager_external_client_no_cleanup() -> None:
    """Test that IdentityManagerAsync does NOT close an external client on exit."""
    config = CoreasonClientConfig(domain="test.auth0.com", audience="aud", client_id="cid")
    external_client = AsyncMock(spec=httpx.AsyncClient)

    async with IdentityManagerAsync(config, client=external_client) as mgr:
        assert mgr._internal_client is False
        assert mgr._client == external_client

    external_client.aclose.assert_not_awaited()
