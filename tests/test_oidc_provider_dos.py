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

from coreason_identity.oidc_provider import OIDCProvider


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.fixture
def provider(mock_client: AsyncMock) -> OIDCProvider:
    return OIDCProvider(
        "https://idp/.well-known/openid-configuration",
        mock_client,
        refresh_cooldown=10.0,  # Set explicit cooldown
    )


@pytest.mark.asyncio
async def test_get_jwks_rate_limiting(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    # Setup mocks
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["key1"]}),
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["key2"]}),
    ]

    # 1. First call - Real time
    jwks1 = await provider.get_jwks(force_refresh=True)
    assert jwks1 == {"keys": ["key1"]}
    assert mock_client.get.call_count == 2

    # Capture the time set in provider
    last_update = provider._last_update
    assert last_update > 0

    # 2. Immediate second call
    # Force time to be just 1 second after last update
    with patch("time.time", return_value=last_update + 1.0):
        jwks2 = await provider.get_jwks(force_refresh=True)
        assert jwks2 == {"keys": ["key1"]}  # Should return cached
        assert mock_client.get.call_count == 2  # No new calls

    # 3. After cooldown
    # Force time to be 11 seconds after last update (cooldown is 10s)
    with patch("time.time", return_value=last_update + 11.0):
        jwks3 = await provider.get_jwks(force_refresh=True)
        assert jwks3 == {"keys": ["key2"]}  # Should fetch new
        assert mock_client.get.call_count == 4
