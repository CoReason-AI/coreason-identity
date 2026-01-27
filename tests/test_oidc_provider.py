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
from typing import Any
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from httpx import Response

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.oidc_provider import OIDCProvider


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.fixture
def oidc_provider(mock_client: AsyncMock) -> OIDCProvider:
    return OIDCProvider(discovery_url="https://test.auth0.com/.well-known/openid-configuration", client=mock_client)


def test_initialization(mock_client: AsyncMock) -> None:
    provider = OIDCProvider(
        discovery_url="https://test.auth0.com/.well-known/openid-configuration", client=mock_client, cache_ttl=1800
    )
    assert provider.discovery_url == "https://test.auth0.com/.well-known/openid-configuration"
    assert provider.cache_ttl == 1800
    assert provider._jwks_cache is None
    assert provider._last_update == 0.0
    assert provider.client is mock_client


@pytest.mark.asyncio
async def test_get_jwks_success(mock_client: AsyncMock, oidc_provider: OIDCProvider) -> None:
    # Setup mocks
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"jwks_uri": "https://test.auth0.com/.well-known/jwks.json"}

    mock_jwks_response = Mock(spec=Response)
    mock_jwks_response.raise_for_status.return_value = None
    mock_jwks_response.json.return_value = {"keys": [{"kid": "123", "kty": "RSA"}]}

    # Configure side_effect for consecutive calls
    mock_client.get.side_effect = [mock_config_response, mock_jwks_response]

    # Execute
    jwks = await oidc_provider.get_jwks()

    # Verify
    assert jwks == {"keys": [{"kid": "123", "kty": "RSA"}]}
    assert oidc_provider._jwks_cache == jwks
    assert oidc_provider._last_update > 0.0
    assert mock_client.get.call_count == 2
    mock_client.get.assert_any_call("https://test.auth0.com/.well-known/openid-configuration")
    mock_client.get.assert_any_call("https://test.auth0.com/.well-known/jwks.json")


@pytest.mark.asyncio
async def test_get_jwks_caching(mock_client: AsyncMock, oidc_provider: OIDCProvider) -> None:
    # Setup mocks
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"jwks_uri": "https://test.auth0.com/.well-known/jwks.json"}

    mock_jwks_response = Mock(spec=Response)
    mock_jwks_response.raise_for_status.return_value = None
    mock_jwks_response.json.return_value = {"keys": [{"kid": "123", "kty": "RSA"}]}

    mock_client.get.side_effect = [mock_config_response, mock_jwks_response]

    # First call - fetches from network
    jwks1 = await oidc_provider.get_jwks()
    assert mock_client.get.call_count == 2

    # Second call - should use cache
    jwks2 = await oidc_provider.get_jwks()
    assert jwks1 == jwks2
    assert mock_client.get.call_count == 2  # Count should remain 2


@pytest.mark.asyncio
async def test_get_jwks_force_refresh(mock_client: AsyncMock, oidc_provider: OIDCProvider) -> None:
    # Setup mocks
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"jwks_uri": "https://test.auth0.com/.well-known/jwks.json"}

    mock_jwks_response = Mock(spec=Response)
    mock_jwks_response.raise_for_status.return_value = None
    mock_jwks_response.json.return_value = {"keys": [{"kid": "123", "kty": "RSA"}]}

    # We expect 2 cycles of calls (config, jwks, config, jwks)
    mock_client.get.side_effect = [mock_config_response, mock_jwks_response, mock_config_response, mock_jwks_response]

    # First call
    await oidc_provider.get_jwks()
    assert mock_client.get.call_count == 2

    # Force refresh
    await oidc_provider.get_jwks(force_refresh=True)
    assert mock_client.get.call_count == 4


@pytest.mark.asyncio
async def test_get_jwks_cache_expiration(mock_client: AsyncMock, oidc_provider: OIDCProvider) -> None:
    # Setup mocks
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"jwks_uri": "https://test.auth0.com/.well-known/jwks.json"}

    mock_jwks_response = Mock(spec=Response)
    mock_jwks_response.raise_for_status.return_value = None
    mock_jwks_response.json.return_value = {"keys": [{"kid": "123", "kty": "RSA"}]}

    mock_client.get.side_effect = [mock_config_response, mock_jwks_response, mock_config_response, mock_jwks_response]

    # Set a short TTL for testing
    oidc_provider.cache_ttl = 0.1  # type: ignore[assignment]

    # First call
    await oidc_provider.get_jwks()
    assert mock_client.get.call_count == 2

    # Manually expire the cache
    import time

    oidc_provider._last_update = float(time.time() - 4000)
    oidc_provider.cache_ttl = 3600

    # Second call - should refetch
    await oidc_provider.get_jwks()
    assert mock_client.get.call_count == 4


@pytest.mark.asyncio
async def test_fetch_oidc_config_failure(mock_client: AsyncMock, oidc_provider: OIDCProvider) -> None:
    mock_client.get.side_effect = httpx.HTTPError("Network error")

    with pytest.raises(CoreasonIdentityError) as exc_info:
        await oidc_provider.get_jwks()

    assert "Failed to fetch OIDC configuration" in str(exc_info.value)


@pytest.mark.asyncio
async def test_fetch_jwks_failure(mock_client: AsyncMock, oidc_provider: OIDCProvider) -> None:
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"jwks_uri": "https://test.auth0.com/.well-known/jwks.json"}

    mock_client.get.side_effect = [mock_config_response, httpx.HTTPError("Network error")]

    with pytest.raises(CoreasonIdentityError) as exc_info:
        await oidc_provider.get_jwks()

    assert "Failed to fetch JWKS" in str(exc_info.value)


@pytest.mark.asyncio
async def test_missing_jwks_uri(mock_client: AsyncMock, oidc_provider: OIDCProvider) -> None:
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"other_field": "value"}

    mock_client.get.return_value = mock_config_response

    with pytest.raises(CoreasonIdentityError) as exc_info:
        await oidc_provider.get_jwks()

    assert "OIDC configuration does not contain 'jwks_uri'" in str(exc_info.value)


@pytest.mark.asyncio
async def test_get_jwks_double_checked_lock_hit(mock_client: AsyncMock, oidc_provider: OIDCProvider) -> None:
    """
    Test that the double-check locking logic works.
    We simulate a race condition where cache is invalid initially,
    but becomes valid just before the lock is acquired.
    """
    # Simulate cache valid state but _jwks_cache initially None
    oidc_provider._jwks_cache = None
    oidc_provider._last_update = 0.0

    valid_keys = {"keys": [{"kid": "race"}]}

    # We need to simulate that after entering the lock, the cache is magically populated
    # by another thread/task.

    original_lock = oidc_provider._lock

    class FakeLock:
        async def __aenter__(self) -> None:
            # Simulate another thread updated it
            oidc_provider._jwks_cache = valid_keys
            oidc_provider._last_update = time.time()
            return None

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    oidc_provider._lock = FakeLock()  # type: ignore

    # Now call get_jwks without force_refresh
    # It will see cache is None (outside lock), enter lock (FakeLock updates cache),
    # check cache again (inside lock logic), find it valid, and return it.

    result = await oidc_provider.get_jwks()

    assert result == valid_keys
    # Verify no network calls made
    mock_client.get.assert_not_called()

    # Restore lock just in case
    oidc_provider._lock = original_lock
