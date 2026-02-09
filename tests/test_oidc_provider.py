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
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models_internal import OIDCConfig
from coreason_identity.oidc_provider import OIDCProvider


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


from collections.abc import Generator


@pytest.fixture
def mock_fetch() -> Generator[AsyncMock, None, None]:
    with patch("coreason_identity.oidc_provider.safe_json_fetch", new_callable=AsyncMock) as m:
        yield m


@pytest.fixture
def provider(mock_client: AsyncMock) -> OIDCProvider:
    # Use shorter retry cooldown/wait for tests
    return OIDCProvider("https://idp/.well-known/openid-configuration", mock_client)


@pytest.mark.asyncio
async def test_get_jwks_success(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    # Mock OIDC config response and JWKS response (direct dicts, not Response objects)
    mock_fetch.side_effect = [
        {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"},
        {"keys": []},
    ]

    jwks = await provider.get_jwks()
    assert jwks == {"keys": []}
    assert mock_fetch.call_count == 2


@pytest.mark.asyncio
async def test_get_jwks_cache_hit(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    # Populate cache
    provider._jwks_cache = {"keys": ["cached"]}
    provider._last_update = time.time()

    jwks = await provider.get_jwks()
    assert jwks == {"keys": ["cached"]}
    assert mock_fetch.call_count == 0


@pytest.mark.asyncio
async def test_get_jwks_force_refresh(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    provider._jwks_cache = {"keys": ["cached"]}
    # Ensure update is old enough to bypass cooldown
    provider._last_update = time.time() - 31.0

    mock_fetch.side_effect = [
        {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"},
        {"keys": ["fresh"]},
    ]

    jwks = await provider.get_jwks(force_refresh=True)
    assert jwks == {"keys": ["fresh"]}


@pytest.mark.asyncio
async def test_get_jwks_expired_cache(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    provider._jwks_cache = {"keys": ["cached"]}
    provider._last_update = time.time() - 3601  # Expired

    mock_fetch.side_effect = [
        {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"},
        {"keys": ["fresh"]},
    ]

    jwks = await provider.get_jwks()
    assert jwks == {"keys": ["fresh"]}


@pytest.mark.asyncio
async def test_fetch_oidc_config_error(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    # Side effect as exception instance raises it every time
    mock_fetch.side_effect = httpx.HTTPError("Network error")

    # Patch sleep to avoid waiting during retries
    with (
        patch("anyio.sleep", new_callable=AsyncMock),
        pytest.raises(CoreasonIdentityError, match="Failed to fetch OIDC configuration"),
    ):
        await provider.get_jwks()


@pytest.mark.asyncio
async def test_missing_jwks_uri(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    # Missing jwks_uri
    mock_fetch.return_value = {}

    with pytest.raises(CoreasonIdentityError, match="Invalid OIDC configuration"):
        await provider.get_jwks()


@pytest.mark.asyncio
async def test_fetch_jwks_error(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    # 1 success (config), then 3 failures (jwks retries)
    mock_fetch.side_effect = [
        {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"},
        httpx.HTTPError("Network error 1"),
        httpx.HTTPError("Network error 2"),
        httpx.HTTPError("Network error 3"),
    ]

    with (
        patch("anyio.sleep", new_callable=AsyncMock),
        pytest.raises(CoreasonIdentityError, match="Failed to fetch JWKS"),
    ):
        await provider.get_jwks()


@pytest.mark.asyncio
async def test_get_issuer_success(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    """Test retrieving issuer from fresh fetch."""
    mock_fetch.side_effect = [
        {"jwks_uri": "https://idp/jwks", "issuer": "https://idp.com"},
        {"keys": []},
    ]

    issuer = await provider.get_issuer()
    assert issuer == "https://idp.com"
    # Ensure cache was populated (both config and JWKS)
    assert provider._oidc_config_cache is not None
    assert provider._jwks_cache is not None


@pytest.mark.asyncio
async def test_get_issuer_from_cache(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    """Test retrieving issuer from existing valid cache."""
    provider._oidc_config_cache = OIDCConfig(issuer="https://cached-idp.com", jwks_uri="...")
    provider._jwks_cache = {"keys": []}
    provider._last_update = time.time()

    issuer = await provider.get_issuer()
    assert issuer == "https://cached-idp.com"
    mock_fetch.assert_not_called()


@pytest.mark.asyncio
async def test_get_issuer_missing_in_config(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    """Test error when 'issuer' is missing from OIDC config."""
    mock_fetch.side_effect = [
        {"jwks_uri": "https://idp/jwks"},  # No issuer
        {"keys": []},
    ]

    with pytest.raises(CoreasonIdentityError, match="Invalid OIDC configuration"):
        await provider.get_issuer()


@pytest.mark.asyncio
async def test_get_issuer_refreshes_if_expired(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    """Test that it refreshes if cache is expired."""
    provider._oidc_config_cache = OIDCConfig(issuer="old", jwks_uri="...")
    provider._jwks_cache = {}
    provider._last_update = time.time() - 3601  # Expired

    mock_fetch.side_effect = [
        {"jwks_uri": "https://idp/jwks", "issuer": "new"},
        {"keys": []},
    ]

    issuer = await provider.get_issuer()
    assert issuer == "new"
    assert mock_fetch.call_count == 2


@pytest.mark.asyncio
async def test_get_issuer_fails_if_config_none(provider: OIDCProvider) -> None:
    """
    Test fallback error if config remains None after attempt.
    """
    with (
        patch.object(provider, "get_jwks", new=AsyncMock()),
        pytest.raises(CoreasonIdentityError, match="Failed to load OIDC configuration"),
    ):
        await provider.get_issuer()


@pytest.mark.asyncio
async def test_get_jwks_double_check_locking(provider: OIDCProvider, mock_fetch: AsyncMock) -> None:
    """
    Test the double-checked locking inside the lock.
    """
    if provider._lock is None:
        import anyio

        provider._lock = anyio.Lock()

    provider._jwks_cache = {"keys": ["old"]}
    provider._last_update = 0  # Expired

    await provider._lock.acquire()

    try:
        task = asyncio.create_task(provider.get_jwks())
        await asyncio.sleep(0)
        provider._jwks_cache = {"keys": ["race_winner"]}
        provider._last_update = time.time()

    finally:
        provider._lock.release()

    jwks = await task

    assert jwks == {"keys": ["race_winner"]}
    mock_fetch.assert_not_called()
