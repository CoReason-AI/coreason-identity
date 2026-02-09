# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from collections.abc import AsyncGenerator
from typing import cast
from unittest.mock import AsyncMock, Mock, patch

import pytest

from coreason_identity.config import CoreasonClientConfig, CoreasonVerifierConfig
from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.manager import IdentityManager
from coreason_identity.models import DeviceFlowResponse, TokenResponse, UserContext

# Mock data
MOCK_DOMAIN = "test.auth0.com"
MOCK_AUDIENCE = "test-audience"
MOCK_CLIENT_ID = "test-client-id"
MOCK_TOKEN = "valid.token.string"
MOCK_AUTH_HEADER = f"Bearer {MOCK_TOKEN}"
MOCK_PII_SALT = "test-suite-mandatory-salt-123"


@pytest.fixture
def client_config() -> CoreasonClientConfig:
    return CoreasonClientConfig(domain=MOCK_DOMAIN, audience=MOCK_AUDIENCE, client_id=MOCK_CLIENT_ID, http_timeout=5.0)


@pytest.fixture
def verifier_config() -> CoreasonVerifierConfig:
    return CoreasonVerifierConfig(
        domain=MOCK_DOMAIN,
        audience=MOCK_AUDIENCE,
        pii_salt=MOCK_PII_SALT,
        allowed_algorithms=["RS256"],
        http_timeout=5.0,
    )


@pytest.fixture
async def client_manager(client_config: CoreasonClientConfig) -> AsyncGenerator[IdentityManager, None]:
    # Mock internal components during initialization
    with (
        patch("coreason_identity.manager.OIDCProvider"),
        # TokenValidator should NOT be called for ClientConfig
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
    ):
        mgr = IdentityManager(client_config)
        yield mgr


@pytest.fixture
async def verifier_manager(verifier_config: CoreasonVerifierConfig) -> AsyncGenerator[IdentityManager, None]:
    # Mock internal components during initialization
    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
    ):
        mgr = IdentityManager(verifier_config)
        yield mgr


def test_init_client(client_config: CoreasonClientConfig) -> None:
    with (
        patch("coreason_identity.manager.OIDCProvider") as MockOIDC,
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
    ):
        mgr = IdentityManager(client_config)

        MockOIDC.assert_called_once()
        assert MockOIDC.call_args[0][0] == f"https://{MOCK_DOMAIN}/.well-known/openid-configuration"

        # Validator should NOT be initialized for client config
        MockValidator.assert_not_called()
        assert mgr.config == client_config
        assert mgr.validator is None


def test_init_verifier(verifier_config: CoreasonVerifierConfig) -> None:
    with (
        patch("coreason_identity.manager.OIDCProvider") as MockOIDC,
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
    ):
        mgr = IdentityManager(verifier_config)

        MockOIDC.assert_called_once()
        MockValidator.assert_called_once()
        assert mgr.config == verifier_config
        assert mgr.validator is not None


@pytest.mark.asyncio
async def test_validate_token_success(verifier_manager: IdentityManager) -> None:
    # Setup mocks
    mock_claims = {"sub": "user123", "email": "test@example.com"}
    mock_user_context = UserContext(user_id="user123", email="test@example.com")

    # Manager.validator is in manager.validator
    assert verifier_manager.validator is not None
    verifier_manager.validator.validate_token = AsyncMock(return_value=mock_claims)  # type: ignore[method-assign]

    # Cast identity_mapper to Mock for type safety or use ignore
    mock_mapper = cast("Mock", verifier_manager.identity_mapper)
    mock_mapper.map_claims.return_value = mock_user_context

    result = await verifier_manager.validate_token(MOCK_AUTH_HEADER)

    verifier_manager.validator.validate_token.assert_awaited_once_with(MOCK_TOKEN)
    mock_mapper.map_claims.assert_called_once_with(mock_claims, token=MOCK_TOKEN)
    assert result == mock_user_context


@pytest.mark.asyncio
async def test_validate_token_invalid_header_format(verifier_manager: IdentityManager) -> None:
    with pytest.raises(InvalidTokenError, match=r"Invalid Authorization header format\. Must start with 'Bearer '"):
        await verifier_manager.validate_token("InvalidHeader")

    with pytest.raises(InvalidTokenError, match="Missing Authorization header"):
        await verifier_manager.validate_token("")


@pytest.mark.asyncio
async def test_validate_token_delegates_exceptions(verifier_manager: IdentityManager) -> None:
    assert verifier_manager.validator is not None
    verifier_manager.validator.validate_token = AsyncMock(side_effect=InvalidTokenError("Token invalid"))  # type: ignore[method-assign]

    with pytest.raises(InvalidTokenError):
        await verifier_manager.validate_token(MOCK_AUTH_HEADER)


@pytest.mark.asyncio
async def test_validate_token_unconfigured(client_manager: IdentityManager) -> None:
    """Test that validate_token raises error if initialized with ClientConfig."""
    with pytest.raises(CoreasonIdentityError, match="Token validation is not configured"):
        await client_manager.validate_token(MOCK_AUTH_HEADER)


@pytest.mark.asyncio
async def test_start_device_login_success(client_manager: IdentityManager) -> None:
    mock_response = DeviceFlowResponse(
        device_code="dcode", user_code="ucode", verification_uri="http://verify", expires_in=300
    )

    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        # The mock instance must be an AsyncMock for async methods
        mock_client_instance = MockClient.return_value
        mock_client_instance.initiate_flow = AsyncMock(return_value=mock_response)

        response = await client_manager.start_device_login(scope="openid profile email")

        # Check call args
        MockClient.assert_called_with(
            client_id=MOCK_CLIENT_ID,
            idp_url=f"https://{MOCK_DOMAIN}",
            client=client_manager._client,
            scope="openid profile email",
        )
        mock_client_instance.initiate_flow.assert_awaited_with(audience=MOCK_AUDIENCE)
        assert response == mock_response


@pytest.mark.asyncio
async def test_start_device_login_custom_scope(client_manager: IdentityManager) -> None:
    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        mock_client_instance = MockClient.return_value
        mock_client_instance.initiate_flow = AsyncMock()

        await client_manager.start_device_login(scope="read:reports")

        MockClient.assert_called_with(
            client_id=MOCK_CLIENT_ID,
            idp_url=f"https://{MOCK_DOMAIN}",
            client=client_manager._client,
            scope="read:reports",
        )


@pytest.mark.asyncio
async def test_start_device_login_recreation(client_manager: IdentityManager) -> None:
    """Test that calling start_device_login twice does NOT recreate the client (reusable)."""
    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        mock_client_instance = MockClient.return_value
        mock_client_instance.initiate_flow = AsyncMock()

        # First call
        await client_manager.start_device_login(scope="openid profile email")
        assert MockClient.call_count == 1

        # Second call
        await client_manager.start_device_login(scope="read:reports")
        # Should NOT recreate per instructions "assume the client is reusable"
        assert MockClient.call_count == 1


@pytest.mark.asyncio
async def test_start_device_login_missing_client_id(verifier_manager: IdentityManager) -> None:
    # verifier_manager uses CoreasonVerifierConfig which does NOT have client_id
    with pytest.raises(CoreasonIdentityError, match="Device login requires CoreasonClientConfig"):
        await verifier_manager.start_device_login(scope="openid profile email")


@pytest.mark.asyncio
async def test_await_device_token_success(client_manager: IdentityManager) -> None:
    mock_flow = DeviceFlowResponse(
        device_code="dcode", user_code="ucode", verification_uri="http://verify", expires_in=300
    )
    mock_token_response = TokenResponse(access_token="access", token_type="Bearer", expires_in=3600)

    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        mock_client_instance = MockClient.return_value
        mock_client_instance.poll_token = AsyncMock(return_value=mock_token_response)

        # Pre-set device_client to simulate state if needed, or rely on auto-creation
        client_manager.device_client = mock_client_instance

        result = await client_manager.await_device_token(mock_flow)

        mock_client_instance.poll_token.assert_awaited_with(mock_flow)
        assert result == mock_token_response


@pytest.mark.asyncio
async def test_await_device_token_stateless(client_manager: IdentityManager) -> None:
    """Test await_device_token without prior start_device_login."""
    mock_flow = DeviceFlowResponse(
        device_code="dcode", user_code="ucode", verification_uri="http://verify", expires_in=300
    )
    mock_token_response = TokenResponse(access_token="access", token_type="Bearer", expires_in=3600)

    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        mock_client_instance = MockClient.return_value
        mock_client_instance.poll_token = AsyncMock(return_value=mock_token_response)

        # Ensure device_client is None
        client_manager.device_client = None

        result = await client_manager.await_device_token(mock_flow)

        # Should have created a new client
        MockClient.assert_called_with(
            client_id=MOCK_CLIENT_ID,
            idp_url=f"https://{MOCK_DOMAIN}",
            client=client_manager._client,
            scope="",  # Scope is not used during polling
        )
        mock_client_instance.poll_token.assert_awaited_with(mock_flow)
        assert result == mock_token_response


@pytest.mark.asyncio
async def test_await_device_token_missing_client_id(verifier_manager: IdentityManager) -> None:
    mock_flow = DeviceFlowResponse(
        device_code="dcode", user_code="ucode", verification_uri="http://verify", expires_in=300
    )

    with pytest.raises(CoreasonIdentityError, match="Device login requires CoreasonClientConfig"):
        await verifier_manager.await_device_token(mock_flow)


def test_init_strict_issuer(verifier_config: CoreasonVerifierConfig) -> None:
    """Test that IdentityManager initializes TokenValidator with strict issuer from config."""
    with (
        patch("coreason_identity.manager.OIDCProvider") as MockOIDC,
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
    ):
        IdentityManager(verifier_config)

        MockOIDC.assert_called_once()
        # Should match derived issuer
        expected_issuer = f"https://{MOCK_DOMAIN}/"
        MockValidator.assert_called_once_with(
            oidc_provider=MockOIDC.return_value,
            audience=MOCK_AUDIENCE,
            issuer=expected_issuer,
            pii_salt=verifier_config.pii_salt,
            allowed_algorithms=verifier_config.allowed_algorithms,
            leeway=verifier_config.clock_skew_leeway,
        )


def test_init_missing_issuer_raises_error() -> None:
    """Test that IdentityManager raises error if issuer configuration is missing."""
    config = Mock(spec=CoreasonVerifierConfig)
    config.domain = "example.com"
    config.issuer = None  # Force None
    config.audience = "aud"
    config.http_timeout = 5.0
    # allow_unsafe_connections removed

    with pytest.raises(CoreasonIdentityError, match="Issuer configuration is missing"):
        IdentityManager(config)


@pytest.mark.asyncio
async def test_start_device_login_no_scope_raises_error(client_manager: IdentityManager) -> None:
    """Test that start_device_login raises ValueError if scope is empty string."""
    with pytest.raises(ValueError, match="Scope must be explicitly provided"):
        await client_manager.start_device_login(scope="")
