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
async def test_startup_refresh_bypass_cooldown(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """
    Edge Case: Startup Cooldown
    Even if (time.time() - 0.0) < cooldown (which is true if time is huge, wait... 0.0 is 1970).
    Actually, _last_update is 0.0. Current time is 2024+. Difference is huge.
    So cooldown check (diff < 30) is FALSE.
    However, if we had a bug where we checked cooldown BEFORE checking if cache exists,
    we might block.
    This test verifies that if cache is None, we fetch regardless of timestamps.
    """
    # Force _last_update to NOW to simulate "we just updated" (but cache is None?)
    # This simulates a state where maybe initialization happened but fetch failed?
    # Or just verifying that "cache is None" takes precedence.
    provider._last_update = time.time()
    provider._jwks_cache = None

    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["startup"]}),
    ]

    jwks = await provider.get_jwks(force_refresh=True)
    assert jwks == {"keys": ["startup"]}
    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_concurrent_refreshes_dos_protection(
    provider: OIDCProvider, mock_client: AsyncMock
) -> None:
    """
    Complex Case: Concurrent Refreshes
    Simulate multiple concurrent tasks calling get_jwks(force_refresh=True).
    The Lock + Cooldown should ensure only ONE network call happens.
    """
    # 1. Setup initial state: Cache is valid but "old" enough to allow ONE refresh if we didn't block
    # Actually, let's start with populated cache and expired cooldown to allow one fetch.
    provider._jwks_cache = {"keys": ["initial"]}
    provider._last_update = time.time() - 31.0  # Cooldown expired

    # 2. Setup Mock with delays to simulate network latency
    # This ensures multiple tasks stack up on the lock
    async def delayed_config(*args, **kwargs):
        await asyncio.sleep(0.1)
        return Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"})

    async def delayed_jwks(*args, **kwargs):
        await asyncio.sleep(0.1)
        return Mock(status_code=200, json=lambda: {"keys": ["refreshed"]})

    mock_client.get.side_effect = [
        # First caller gets these
        await delayed_config(),
        await delayed_jwks(),
        # Subsequent callers should NOT hit network due to cooldown updated by first caller
        # But if they did, they'd get this (we assert they don't)
        Mock(status_code=200, json=lambda: {"error": "Should not be called"}),
    ]
    # We need side_effect to be an iterable or function.
    # To handle async delay correctly in mock:
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["refreshed"]}),
    ]
    # We rely on asyncio.sleep in the test to yield, but we need the fetch itself to be slow
    # to allow others to wait on lock?
    # Actually, checking cooldown happens INSIDE lock.
    # Task 1 enters lock. Updates _last_update. Exits lock.
    # Task 2 enters lock. Checks cooldown. Sees recent update. Returns cache.
    # So we don't need delay inside the fetch for this logic to hold, strictly speaking,
    # provided they are scheduled concurrently.

    # Launch 5 concurrent refresh requests
    tasks = [asyncio.create_task(provider.get_jwks(force_refresh=True)) for _ in range(5)]
    results = await asyncio.gather(*tasks)

    # All should return the new keys
    for res in results:
        assert res == {"keys": ["refreshed"]}

    # Crucially: Network called only twice (Config + JWKS) for the FIRST task.
    # Others hit cache.
    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_failed_refresh_does_not_update_timestamp(
    provider: OIDCProvider, mock_client: AsyncMock
) -> None:
    """
    Complex Case: Failure Handling
    If a refresh fails, _last_update should NOT be updated.
    This ensures that the NEXT attempt (after failure is handled) allows a retry
    instead of blocking for 30s.
    """
    provider._jwks_cache = {"keys": ["old"]}
    provider._last_update = time.time() - 31.0  # Allow refresh

    # Mock failure
    mock_client.get.side_effect = httpx.HTTPError("Network Down")

    # 1. Attempt Refresh - Fails
    with pytest.raises(CoreasonIdentityError):
        await provider.get_jwks(force_refresh=True)

    # Verify timestamp didn't change (still old)
    assert provider._last_update < (time.time() - 30.0)

    # 2. Attempt Refresh again immediately - Should proceed (try to fetch)
    # Because timestamp is still old.
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["new"]}),
    ]

    jwks = await provider.get_jwks(force_refresh=True)
    assert jwks == {"keys": ["new"]}


@pytest.mark.asyncio
async def test_clock_skew_resilience(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """
    Edge Case: Clock Skew
    Simulate system time jumping backwards (e.g., NTP correction).
    current_time - last_update could be negative.
    (negative) < 30.0 is True. So it activates cooldown?
    If time jumps back, we MIGHT block refresh. This is generally acceptable fail-safe.
    """
    provider._jwks_cache = {"keys": ["future"]}
    provider._last_update = time.time() + 3600  # Updated in "future"

    # Request refresh
    # current (now) - last (future) = negative number
    # negative < 30 is TRUE.
    # So it should return cached keys and NOT fetch.

    mock_client.get.side_effect = httpx.HTTPError("Should not be called")

    jwks = await provider.get_jwks(force_refresh=True)
    assert jwks == {"keys": ["future"]}
    mock_client.get.assert_not_called()
