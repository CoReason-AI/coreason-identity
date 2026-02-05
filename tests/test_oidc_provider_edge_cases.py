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

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.oidc_provider import OIDCProvider


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.fixture
def provider(mock_client: AsyncMock) -> OIDCProvider:
    return OIDCProvider("https://idp/.well-known/openid-configuration", mock_client, refresh_cooldown=10.0)


@pytest.mark.asyncio
async def test_cooldown_disabled(mock_client: AsyncMock) -> None:
    """Test that cooldown=0 effectively disables the rate limit."""
    provider = OIDCProvider("url", mock_client, refresh_cooldown=0.0)
    provider._jwks_cache = {"keys": ["init"]}
    provider._last_refresh_attempt = 1000.0

    # Mock responses for 2 consecutive calls
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["fresh1"]}),
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["fresh2"]}),
    ]

    with patch("time.time", return_value=1000.1):
        jwks1 = await provider.get_jwks(force_refresh=True)
        jwks2 = await provider.get_jwks(force_refresh=True)

    assert jwks1 == {"keys": ["fresh1"]}
    assert jwks2 == {"keys": ["fresh2"]}
    assert mock_client.get.call_count == 4


@pytest.mark.asyncio
async def test_runtime_cooldown_change(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """Test changing refresh_cooldown at runtime."""
    provider._jwks_cache = {"keys": ["cached"]}
    provider._last_refresh_attempt = 1000.0

    # 1. Initial state: within 10s cooldown
    with patch("time.time", return_value=1005.0):
        await provider.get_jwks(force_refresh=True)
        mock_client.get.assert_not_called()

    # 2. Relax constraint
    provider.refresh_cooldown = 1.0
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["fresh"]}),
    ]

    # 3. Should now fetch
    with patch("time.time", return_value=1005.0):
        jwks = await provider.get_jwks(force_refresh=True)
        assert jwks == {"keys": ["fresh"]}


@pytest.mark.asyncio
async def test_negative_elapsed_time(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """Test protection against clock skew/jumps (negative elapsed time)."""
    provider._jwks_cache = {"keys": ["cached"]}
    # Last update in future (simulating clock jump back)
    provider._last_refresh_attempt = 2000.0

    # Current time is 1000.0. Diff is -1000.0 which is < 10.0
    # Should trigger cooldown
    with patch("time.time", return_value=1000.0):
        jwks = await provider.get_jwks(force_refresh=True)
        assert jwks == {"keys": ["cached"]}
        mock_client.get.assert_not_called()


@pytest.mark.asyncio
async def test_failure_updates_attempt_timestamp(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """
    Verify that even if the fetch fails, _last_refresh_attempt is updated
    so we don't immediately retry (DoS protection for IdP).
    """
    provider._jwks_cache = {"keys": ["cached"]}

    # 1. First call fails
    mock_client.get.side_effect = httpx.HTTPError("IdP Down")

    start_time = 1000.0
    with patch("time.time", return_value=start_time):
        with pytest.raises(CoreasonIdentityError):
            await provider.get_jwks(force_refresh=True)

    # _last_refresh_attempt should be updated
    assert provider._last_refresh_attempt == start_time

    # 2. Immediate retry should be blocked (Fail-Cached)
    # Reset mock to return success if called (which it shouldn't be)
    mock_client.get.side_effect = None
    mock_client.get.return_value = Mock(status_code=200, json=lambda: {})

    with patch("time.time", return_value=start_time + 1.0):
        # Even though previous failed, we respect cooldown
        jwks = await provider.get_jwks(force_refresh=True)
        assert jwks == {"keys": ["cached"]}
        # Should not have called client again
        assert mock_client.get.call_count == 1  # Only the first failed call
