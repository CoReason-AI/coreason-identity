# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from typing import Any, Generator
from unittest.mock import patch

import pytest

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.manager import IdentityManager
from coreason_identity.models import DeviceFlowResponse, TokenResponse, UserContext

# Mock data
MOCK_DOMAIN = "test.auth0.com"
MOCK_AUDIENCE = "test-audience"
MOCK_CLIENT_ID = "test-client-id"
MOCK_TOKEN = "valid.token.string"
MOCK_AUTH_HEADER = f"Bearer {MOCK_TOKEN}"


@pytest.fixture  # type: ignore[misc]
def config() -> CoreasonIdentityConfig:
    return CoreasonIdentityConfig(domain=MOCK_DOMAIN, audience=MOCK_AUDIENCE, client_id=MOCK_CLIENT_ID)


@pytest.fixture  # type: ignore[misc]
def manager(config: CoreasonIdentityConfig) -> Generator[IdentityManager, Any, None]:
    # Mock internal components during initialization
    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
    ):
        mgr = IdentityManager(config)
        yield mgr


def test_init(config: CoreasonIdentityConfig) -> None:
    with (
        patch("coreason_identity.manager.OIDCProvider") as MockOIDC,
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
    ):
        mgr = IdentityManager(config)

        MockOIDC.assert_called_once_with(f"https://{MOCK_DOMAIN}/.well-known/openid-configuration")
        MockValidator.assert_called_once()
        assert mgr.config == config


def test_validate_token_success(manager: IdentityManager) -> None:
    # Setup mocks
    mock_claims = {"sub": "user123", "email": "test@example.com"}
    mock_user_context = UserContext(sub="user123", email="test@example.com")

    manager.validator.validate_token.return_value = mock_claims  # type: ignore[attr-defined]
    manager.identity_mapper.map_claims.return_value = mock_user_context  # type: ignore[attr-defined]

    result = manager.validate_token(MOCK_AUTH_HEADER)

    manager.validator.validate_token.assert_called_once_with(MOCK_TOKEN)  # type: ignore[attr-defined]
    manager.identity_mapper.map_claims.assert_called_once_with(mock_claims)  # type: ignore[attr-defined]
    assert result == mock_user_context


def test_validate_token_invalid_header_format(manager: IdentityManager) -> None:
    with pytest.raises(InvalidTokenError, match="Missing or invalid Authorization header"):
        manager.validate_token("InvalidHeader")

    with pytest.raises(InvalidTokenError, match="Missing or invalid Authorization header"):
        manager.validate_token("")


def test_validate_token_delegates_exceptions(manager: IdentityManager) -> None:
    manager.validator.validate_token.side_effect = InvalidTokenError("Token invalid")  # type: ignore[attr-defined]

    with pytest.raises(InvalidTokenError):
        manager.validate_token(MOCK_AUTH_HEADER)


def test_start_device_login_success(manager: IdentityManager) -> None:
    mock_response = DeviceFlowResponse(
        device_code="dcode", user_code="ucode", verification_uri="http://verify", expires_in=300
    )

    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        mock_client_instance = MockClient.return_value
        mock_client_instance.initiate_flow.return_value = mock_response

        response = manager.start_device_login()

        MockClient.assert_called_with(
            client_id=MOCK_CLIENT_ID, idp_url=f"https://{MOCK_DOMAIN}", scope="openid profile email"
        )
        mock_client_instance.initiate_flow.assert_called_with(audience=MOCK_AUDIENCE)
        assert response == mock_response


def test_start_device_login_custom_scope(manager: IdentityManager) -> None:
    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        manager.start_device_login(scope="custom:scope")

        MockClient.assert_called_with(client_id=MOCK_CLIENT_ID, idp_url=f"https://{MOCK_DOMAIN}", scope="custom:scope")


def test_start_device_login_recreation(manager: IdentityManager) -> None:
    """Test that calling start_device_login twice recreates the client."""
    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        # First call
        manager.start_device_login()
        assert MockClient.call_count == 1

        # Second call
        manager.start_device_login(scope="new:scope")
        assert MockClient.call_count == 2

        # Verify the second call used the new scope
        MockClient.assert_called_with(client_id=MOCK_CLIENT_ID, idp_url=f"https://{MOCK_DOMAIN}", scope="new:scope")


def test_start_device_login_missing_client_id() -> None:
    config_no_client = CoreasonIdentityConfig(domain=MOCK_DOMAIN, audience=MOCK_AUDIENCE)

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
    ):
        mgr = IdentityManager(config_no_client)

        with pytest.raises(CoreasonIdentityError, match="client_id is required"):
            mgr.start_device_login()


def test_await_device_token_success(manager: IdentityManager) -> None:
    mock_flow = DeviceFlowResponse(
        device_code="dcode", user_code="ucode", verification_uri="http://verify", expires_in=300
    )
    mock_token_response = TokenResponse(access_token="access", token_type="Bearer", expires_in=3600)

    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        mock_client_instance = MockClient.return_value
        mock_client_instance.poll_token.return_value = mock_token_response

        # Pre-set device_client to simulate state if needed, or rely on auto-creation
        manager.device_client = mock_client_instance

        result = manager.await_device_token(mock_flow)

        mock_client_instance.poll_token.assert_called_with(mock_flow)
        assert result == mock_token_response


def test_await_device_token_stateless(manager: IdentityManager) -> None:
    """Test await_device_token without prior start_device_login."""
    mock_flow = DeviceFlowResponse(
        device_code="dcode", user_code="ucode", verification_uri="http://verify", expires_in=300
    )
    mock_token_response = TokenResponse(access_token="access", token_type="Bearer", expires_in=3600)

    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        mock_client_instance = MockClient.return_value
        mock_client_instance.poll_token.return_value = mock_token_response

        # Ensure device_client is None
        manager.device_client = None

        result = manager.await_device_token(mock_flow)

        # Should have created a new client
        MockClient.assert_called_with(client_id=MOCK_CLIENT_ID, idp_url=f"https://{MOCK_DOMAIN}")
        mock_client_instance.poll_token.assert_called_with(mock_flow)
        assert result == mock_token_response


def test_await_device_token_missing_client_id() -> None:
    config_no_client = CoreasonIdentityConfig(domain=MOCK_DOMAIN, audience=MOCK_AUDIENCE)

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
    ):
        mgr = IdentityManager(config_no_client)
        mock_flow = DeviceFlowResponse(
            device_code="dcode", user_code="ucode", verification_uri="http://verify", expires_in=300
        )

        with pytest.raises(CoreasonIdentityError, match="client_id is required"):
            mgr.await_device_token(mock_flow)
