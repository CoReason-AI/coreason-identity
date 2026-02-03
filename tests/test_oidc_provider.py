# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import asyncio
import time
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.oidc_provider import OIDCProvider


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.fixture
def provider(mock_client: AsyncMock) -> OIDCProvider:
    return OIDCProvider("https://idp/.well-known/openid-configuration", mock_client)


@pytest.mark.asyncio
async def test_get_jwks_success(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    # Mock OIDC config response
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": []}),
    ]

    jwks = await provider.get_jwks()
    assert jwks == {"keys": []}
    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_get_jwks_cache_hit(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    # Populate cache
    provider._jwks_cache = {"keys": ["cached"]}
    provider._last_update = time.time()

    jwks = await provider.get_jwks()
    assert jwks == {"keys": ["cached"]}
    assert mock_client.get.call_count == 0


@pytest.mark.asyncio
async def test_get_jwks_force_refresh(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    provider._jwks_cache = {"keys": ["cached"]}
    # Ensure update is old enough to bypass debounce logic
    provider._last_update = time.time() - 3600

    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["fresh"]}),
    ]

    jwks = await provider.get_jwks(force_refresh=True)
    assert jwks == {"keys": ["fresh"]}


@pytest.mark.asyncio
async def test_get_jwks_expired_cache(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    provider._jwks_cache = {"keys": ["cached"]}
    provider._last_update = time.time() - 3601  # Expired

    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["fresh"]}),
    ]

    jwks = await provider.get_jwks()
    assert jwks == {"keys": ["fresh"]}


@pytest.mark.asyncio
async def test_fetch_oidc_config_error(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    mock_client.get.side_effect = httpx.HTTPError("Network error")

    with pytest.raises(CoreasonIdentityError, match="Failed to fetch OIDC configuration"):
        await provider.get_jwks()


@pytest.mark.asyncio
async def test_missing_jwks_uri(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    mock_client.get.return_value = Mock(status_code=200, json=lambda: {})

    with pytest.raises(CoreasonIdentityError, match="OIDC configuration does not contain 'jwks_uri'"):
        await provider.get_jwks()


@pytest.mark.asyncio
async def test_fetch_jwks_error(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        httpx.HTTPError("Network error"),
    ]

    with pytest.raises(CoreasonIdentityError, match="Failed to fetch JWKS"):
        await provider.get_jwks()


@pytest.mark.asyncio
async def test_get_issuer_success(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """Test retrieving issuer from fresh fetch."""
    mock_client.get.side_effect = [
        Mock(
            status_code=200,
            json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "https://idp.com"},
        ),
        Mock(status_code=200, json=lambda: {"keys": []}),
    ]

    issuer = await provider.get_issuer()
    assert issuer == "https://idp.com"
    # Ensure cache was populated (both config and JWKS)
    assert provider._oidc_config_cache is not None
    assert provider._jwks_cache is not None


@pytest.mark.asyncio
async def test_get_issuer_from_cache(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """Test retrieving issuer from existing valid cache."""
    provider._oidc_config_cache = {"issuer": "https://cached-idp.com", "jwks_uri": "..."}
    provider._jwks_cache = {"keys": []}
    provider._last_update = time.time()

    issuer = await provider.get_issuer()
    assert issuer == "https://cached-idp.com"
    mock_client.get.assert_not_called()


@pytest.mark.asyncio
async def test_get_issuer_missing_in_config(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """Test error when 'issuer' is missing from OIDC config."""
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),  # No issuer
        Mock(status_code=200, json=lambda: {"keys": []}),
    ]

    with pytest.raises(CoreasonIdentityError, match="does not contain 'issuer'"):
        await provider.get_issuer()


@pytest.mark.asyncio
async def test_get_issuer_refreshes_if_expired(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """Test that it refreshes if cache is expired."""
    provider._oidc_config_cache = {"issuer": "old", "jwks_uri": "..."}
    provider._jwks_cache = {}
    provider._last_update = time.time() - 3601  # Expired

    mock_client.get.side_effect = [
        Mock(
            status_code=200,
            json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "new"},
        ),
        Mock(status_code=200, json=lambda: {"keys": []}),
    ]

    issuer = await provider.get_issuer()
    assert issuer == "new"
    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_get_issuer_fails_if_config_none(provider: OIDCProvider) -> None:
    """
    Test fallback error if config remains None after attempt.
    This scenario is theoretically unreachable if get_jwks raises on failure,
    but we mock get_jwks to simulate strange state or for coverage.
    """
    # Mock get_jwks to NOT raise but also NOT populate config (simulating a bug or weird state)
    # Since get_jwks implementation *does* populate it or raise, we have to patch it.
    with patch.object(provider, "get_jwks", new=AsyncMock()):
        # get_jwks does nothing, so _oidc_config_cache stays None
        with pytest.raises(CoreasonIdentityError, match="Failed to load OIDC configuration"):
            await provider.get_issuer()


@pytest.mark.asyncio
async def test_get_jwks_double_check_locking(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """
    Test the double-checked locking inside the lock.
    We simulate a race where the cache is updated by another task while the current task is waiting for the lock.
    """
    # 1. Start with invalid cache so we enter the waiting phase
    provider._jwks_cache = {"keys": ["old"]}
    provider._last_update = 0  # Expired

    # 2. Acquire lock manually to block the upcoming get_jwks call
    await provider._lock.acquire()

    try:
        # 3. Schedule get_jwks() in background
        task = asyncio.create_task(provider.get_jwks())

        # Yield to allow task to start and hit the lock
        await asyncio.sleep(0)

        # 4. Update cache to be valid (simulating another thread finished refreshing)
        provider._jwks_cache = {"keys": ["race_winner"]}
        provider._last_update = time.time()

    finally:
        # 5. Release lock, allowing background task to proceed
        provider._lock.release()

    # 6. Await result
    jwks = await task

    # 7. Assert it used the cache we set, NOT fetching new one
    assert jwks == {"keys": ["race_winner"]}
    mock_client.get.assert_not_called()
