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
from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.manager import IdentityManager
from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.models import DeviceFlowResponse, TokenResponse

@pytest.fixture
def config():
    return CoreasonIdentityConfig(domain="test.com", audience="aud", client_id="cid")

def test_manager_sync_usage(config):
    with patch("coreason_identity.manager.IdentityManagerAsync") as MockAsync:
        mock_instance = MockAsync.return_value
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock()
        mock_instance.validate_token = AsyncMock(return_value="user_ctx")

        mgr = IdentityManager(config)

        with mgr:
            res = mgr.validate_token("token")

        assert res == "user_ctx"
        mock_instance.__aenter__.assert_called_once()
        mock_instance.__aexit__.assert_called_once()
        mock_instance.validate_token.assert_awaited_once()

def test_manager_sync_no_context_fail(config):
    mgr = IdentityManager(config)
    with pytest.raises(CoreasonIdentityError, match="Context not started"):
        mgr.validate_token("token")

def test_init_strict_issuer(config):
    with patch("coreason_identity.manager.OIDCProviderAsync") as MockOIDC, \
         patch("coreason_identity.manager.TokenValidatorAsync") as MockValidator:

        from coreason_identity.manager import IdentityManagerAsync
        IdentityManagerAsync(config)

        expected_issuer = "https://test.com/"
        MockValidator.assert_called_once()
        args, kwargs = MockValidator.call_args
        assert kwargs["issuer"] == expected_issuer

def test_device_flow_methods(config):
    with patch("coreason_identity.manager.IdentityManagerAsync") as MockAsync:
        mock_instance = MockAsync.return_value
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock()

        flow_resp = DeviceFlowResponse(
             device_code="dc", user_code="uc", verification_uri="uri", expires_in=300, interval=5
        )
        token_resp = TokenResponse(access_token="at", token_type="Bearer", expires_in=3600)

        mock_instance.start_device_login = AsyncMock(return_value=flow_resp)
        mock_instance.await_device_token = AsyncMock(return_value=token_resp)

        mgr = IdentityManager(config)

        with mgr:
            f = mgr.start_device_login()
            t = mgr.await_device_token(f)

        assert f == flow_resp
        assert t == token_resp
        mock_instance.start_device_login.assert_awaited_once()
        mock_instance.await_device_token.assert_awaited_once()

def test_validate_token_invalid_header(config):
    # This logic is in IdentityManagerAsync.validate_token
    # We should test IdentityManagerAsync directly for logic coverage
    from coreason_identity.manager import IdentityManagerAsync
    mgr = IdentityManagerAsync(config)

    import asyncio
    with pytest.raises(InvalidTokenError):
        asyncio.run(mgr.validate_token("Invalid"))
