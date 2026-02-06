# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import time
from unittest.mock import AsyncMock, Mock

import anyio
import httpx
import pytest

from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.utils.logger import logger


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.fixture
def provider(mock_client: AsyncMock) -> OIDCProvider:
    return OIDCProvider("https://idp/.well-known/openid-configuration", mock_client)


@pytest.mark.asyncio
async def test_lazy_lock_initialization(mock_client: AsyncMock) -> None:
    """
    Verify that _lock is None on init and initialized inside get_jwks.
    This prevents "Future attached to a different loop" errors.
    """
    provider = OIDCProvider("https://idp", mock_client)
    assert provider._lock is None

    # Mock responses to avoid actual network calls
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}),
        Mock(status_code=200, json=lambda: {"keys": []}),
    ]

    await provider.get_jwks()

    assert provider._lock is not None
    assert isinstance(provider._lock, anyio.Lock)


def test_provider_sync_init_async_run(mock_client: AsyncMock) -> None:
    """
    Verify that we can initialize in sync context and run in anyio.run().
    This explicitly tests the fix for Finding #3.
    """
    provider = OIDCProvider("https://idp", mock_client)

    # Mock responses
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}),
        Mock(status_code=200, json=lambda: {"keys": []}),
    ]

    async def run_check() -> None:
        # Should not crash with RuntimeError
        await provider.get_jwks()
        assert provider._lock is not None

    anyio.run(run_check)


@pytest.mark.asyncio
async def test_dos_protection_cooldown(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """
    Verify that force_refresh=True respects the cooldown period (Finding #2).
    """
    # 1. Initial Fetch (Startup)
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}),
        Mock(status_code=200, json=lambda: {"keys": ["v1"]}),
    ]

    jwks1 = await provider.get_jwks(force_refresh=True)
    assert jwks1 == {"keys": ["v1"]}
    assert mock_client.get.call_count == 2

    # 2. Immediate second fetch with force_refresh=True
    # Should hit cooldown and return cached v1 without network call

    # Reset mock to verify calls
    mock_client.get.reset_mock()

    jwks2 = await provider.get_jwks(force_refresh=True)
    assert jwks2 == {"keys": ["v1"]}
    mock_client.get.assert_not_called()

    # 3. Wait/Mock time pass to exceed cooldown
    # Cooldown is default 30s. We manually adjust _last_update to simulate time passing.
    provider._last_update = time.time() - 31.0

    # Setup mock for next fetch
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}),
        Mock(status_code=200, json=lambda: {"keys": ["v2"]}),
    ]

    jwks3 = await provider.get_jwks(force_refresh=True)
    assert jwks3 == {"keys": ["v2"]}
    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_dos_protection_warning_log(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """
    Verify that a warning is logged when cooldown is active.
    """
    logs: list[str] = []
    # Attach a sink to capture logs
    handler_id = logger.add(lambda msg: logs.append(msg))

    try:
        # 1. Initial Fetch
        mock_client.get.side_effect = [
            Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}),
            Mock(status_code=200, json=lambda: {"keys": ["v1"]}),
        ]
        await provider.get_jwks(force_refresh=True)

        # 2. Trigger Cooldown
        await provider.get_jwks(force_refresh=True)

        # Check logs
        assert any("JWKS refresh cooldown active" in str(log) for log in logs)

    finally:
        logger.remove(handler_id)
