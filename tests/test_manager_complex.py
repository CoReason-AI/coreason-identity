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
from unittest.mock import AsyncMock, Mock, patch

import pytest

from coreason_identity.config import CoreasonClientConfig, CoreasonVerifierConfig
from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InvalidTokenError,
    SignatureVerificationError,
    TokenExpiredError,
)
from coreason_identity.manager import IdentityManager
from coreason_identity.models import DeviceFlowResponse

# Mock data
MOCK_DOMAIN = "test.auth0.com"
MOCK_AUDIENCE = "test-audience"
MOCK_CLIENT_ID = "test-client-id"
MOCK_PII_SALT = "test-salt"


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
    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
    ):
        mgr = IdentityManager(client_config)
        yield mgr


@pytest.fixture
async def verifier_manager(verifier_config: CoreasonVerifierConfig) -> AsyncGenerator[IdentityManager, None]:
    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
    ):
        mgr = IdentityManager(verifier_config)
        yield mgr


@pytest.mark.asyncio
async def test_validate_token_mapper_failure(verifier_manager: IdentityManager) -> None:
    """Test when Validator succeeds but Mapper fails (e.g., missing claims)."""
    assert verifier_manager.validator is not None
    # Validator returns a valid dictionary
    verifier_manager.validator.validate_token = AsyncMock(return_value={"sub": "123"})  # type: ignore

    # Mapper raises error (e.g. missing 'email')
    verifier_manager.identity_mapper.map_claims = Mock(side_effect=CoreasonIdentityError("Missing email"))  # type: ignore

    with pytest.raises(CoreasonIdentityError, match="Missing email"):
        await verifier_manager.validate_token("Bearer valid_token")


@pytest.mark.asyncio
async def test_validate_token_specific_exceptions(verifier_manager: IdentityManager) -> None:
    """Test that specific validation exceptions bubble up correctly."""
    assert verifier_manager.validator is not None

    # SignatureVerificationError
    verifier_manager.validator.validate_token = AsyncMock(side_effect=SignatureVerificationError("Bad sig"))  # type: ignore
    with pytest.raises(SignatureVerificationError):
        await verifier_manager.validate_token("Bearer bad_sig")

    # TokenExpiredError
    verifier_manager.validator.validate_token = AsyncMock(side_effect=TokenExpiredError("Expired"))  # type: ignore
    with pytest.raises(TokenExpiredError):
        await verifier_manager.validate_token("Bearer expired")


@pytest.mark.asyncio
async def test_validate_token_header_edge_cases(verifier_manager: IdentityManager) -> None:
    """Test strict header parsing."""

    # Case sensitive "Bearer"
    with pytest.raises(InvalidTokenError, match="Invalid Authorization header format"):
        await verifier_manager.validate_token("bearer token")

    # Missing token part
    assert verifier_manager.validator is not None
    verifier_manager.validator.validate_token = AsyncMock()  # type: ignore
    with pytest.raises(InvalidTokenError):
        await verifier_manager.validate_token("Bearer ")


@pytest.mark.asyncio
async def test_device_login_network_failure(client_manager: IdentityManager) -> None:
    """Test network failure during device flow initiation."""
    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        mock_instance = MockClient.return_value
        mock_instance.initiate_flow = AsyncMock(side_effect=CoreasonIdentityError("Network Error"))

        with pytest.raises(CoreasonIdentityError, match="Network Error"):
            await client_manager.start_device_login(scope="openid profile email")


@pytest.mark.asyncio
async def test_await_device_token_polling_failure(client_manager: IdentityManager) -> None:
    """Test failure during polling (e.g. timeout or denied)."""
    mock_flow = DeviceFlowResponse(device_code="dcode", user_code="ucode", verification_uri="url", expires_in=300)

    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        mock_instance = MockClient.return_value
        mock_instance.poll_token = AsyncMock(side_effect=CoreasonIdentityError("Polling timed out"))

        # Pre-set client
        client_manager.device_client = mock_instance

        with pytest.raises(CoreasonIdentityError, match="Polling timed out"):
            await client_manager.await_device_token(mock_flow)


@pytest.mark.asyncio
async def test_await_device_token_stateless_failure(client_manager: IdentityManager) -> None:
    """Test stateless polling failure propagates error."""
    mock_flow = DeviceFlowResponse(device_code="dcode", user_code="ucode", verification_uri="url", expires_in=300)

    # Ensure no client exists
    client_manager.device_client = None

    with patch("coreason_identity.manager.DeviceFlowClient") as MockClient:
        mock_instance = MockClient.return_value
        mock_instance.poll_token = AsyncMock(side_effect=CoreasonIdentityError("Access denied"))

        with pytest.raises(CoreasonIdentityError, match="Access denied"):
            await client_manager.await_device_token(mock_flow)


@pytest.mark.asyncio
async def test_manager_malformed_bearer_headers(verifier_manager: IdentityManager) -> None:
    """Test IdentityManager rejection of malformed Bearer headers."""
    # We can reuse the 'manager' fixture which is already typed and imported.

    # Mock the validator to avoid actual validation calls if header check passes (it shouldn't)
    verifier_manager.validator = Mock()

    # Case 1: No space
    with pytest.raises(InvalidTokenError, match="Invalid Authorization header format"):
        await verifier_manager.validate_token("BearerToken")

    # Case 2: Lowercase bearer (strict check says 'Bearer ')
    # The code uses `re.match(r"^Bearer\s+(.+)$", auth_header)`
    with pytest.raises(InvalidTokenError, match="Invalid Authorization header format"):
        await verifier_manager.validate_token("bearer token")

    # Case 3: Just "Bearer"
    with pytest.raises(InvalidTokenError, match="Invalid Authorization header format"):
        await verifier_manager.validate_token("Bearer")

    # Case 4: None/Empty (handled by type signature usually, but runtime check exists)
    with pytest.raises(InvalidTokenError, match="Missing Authorization header"):
        await verifier_manager.validate_token("")
