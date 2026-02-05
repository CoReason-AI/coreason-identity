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
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from coreason_identity.oidc_provider import OIDCProvider


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.fixture
def provider(mock_client: AsyncMock) -> OIDCProvider:
    # Initialize with short cooldown for testing
    return OIDCProvider("https://idp/.well-known/openid-configuration", mock_client, refresh_cooldown=10.0)


@pytest.mark.asyncio
async def test_get_jwks_rate_limiting(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    # Setup mock responses
    mock_client.get.side_effect = [
        # First call responses
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["initial"]}),
        # Second call responses (after cooldown)
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["fresh"]}),
    ]

    # Patch time to control the clock
    with patch("time.time") as mock_time:
        start_time = 1000.0
        mock_time.return_value = start_time

        # 1. First call (Initial fetch)
        jwks = await provider.get_jwks(force_refresh=True)
        assert jwks == {"keys": ["initial"]}
        assert mock_client.get.call_count == 2  # 1 for config, 1 for jwks

        # 2. Immediate second call (Should be rate limited)
        mock_time.return_value = start_time + 1.0  # +1s < 10s cooldown

        jwks = await provider.get_jwks(force_refresh=True)
        assert jwks == {"keys": ["initial"]}  # Returns cached
        assert mock_client.get.call_count == 2  # No new calls

        # 3. Call after cooldown
        mock_time.return_value = start_time + 12.0  # +12s > 10s cooldown

        jwks = await provider.get_jwks(force_refresh=True)
        assert jwks == {"keys": ["fresh"]}
        assert mock_client.get.call_count == 4  # +2 new calls
