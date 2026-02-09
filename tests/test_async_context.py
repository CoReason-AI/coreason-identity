# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import pytest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import anyio
import httpx

from coreason_identity.config import CoreasonVerifierConfig
from coreason_identity.manager import IdentityManager
from coreason_identity.oidc_provider import OIDCProvider


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.mark.asyncio
async def test_manager_context_cleanup(mock_client: AsyncMock) -> None:
    """
    Verify that IdentityManager.__aexit__ closes the client.
    """
    config = CoreasonVerifierConfig(
        domain="test.auth0.com",
        audience="test-audience",
        pii_salt="salt",
        http_timeout=5.0,
        allowed_algorithms=["RS256"],
        clock_skew_leeway=0,
        issuer="https://test.auth0.com/",
    )

    RealAsyncClient = httpx.AsyncClient

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
        patch("coreason_identity.manager.HTTPXClientInstrumentor"), # Patch instrumentor
        patch("httpx.AsyncClient") as MockHttpxClient, # Patch httpx.AsyncClient constructor
    ):
        mock_internal_client = MockHttpxClient.return_value
        mock_internal_client.aclose = AsyncMock()

        # Case 1: Internal client (created by manager)
        async with IdentityManager(config) as manager:
            assert manager._internal_client

        mock_internal_client.aclose.assert_awaited_once()

        # Case 2: External client (passed to manager)
        # Use RealAsyncClient for spec
        external_client = AsyncMock(spec=RealAsyncClient)
        async with IdentityManager(config, client=external_client) as manager:
            assert not manager._internal_client

        # Should NOT be closed by manager
        external_client.aclose.assert_not_awaited()


@pytest.mark.asyncio
async def test_oidc_provider_lock_safety(mock_client: AsyncMock) -> None:
    """
    Verify that OIDCProvider uses a lock for get_jwks.
    """
    provider = OIDCProvider("https://idp", mock_client)

    # We mock the critical section to verify lock usage
    with patch.object(
        provider, "_refresh_jwks_critical_section", new_callable=AsyncMock
    ) as mock_critical:
        mock_critical.return_value = {"keys": []}

        # Call get_jwks with force_refresh=True to force lock usage
        await provider.get_jwks(force_refresh=True)

        # Check if lock was created
        assert provider._lock is not None
        assert isinstance(provider._lock, anyio.Lock)
        mock_critical.assert_awaited_once()
