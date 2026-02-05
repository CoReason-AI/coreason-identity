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
from typing import Any, Dict, cast
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from coreason_identity.oidc_provider import OIDCProvider


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


@pytest.fixture
def provider(mock_client: AsyncMock) -> OIDCProvider:
    return OIDCProvider("https://idp/.well-known/openid-configuration", mock_client, refresh_cooldown=10.0)


@pytest.mark.asyncio
async def test_concurrent_force_refresh_calls(provider: OIDCProvider, mock_client: AsyncMock) -> None:
    """
    Test that multiple concurrent calls to get_jwks(force_refresh=True)
    result in only ONE network request, and others receive the cached result.
    This verifies the Lock + Cooldown synergy.
    """
    provider._jwks_cache = {"keys": ["initial"]}
    provider._last_refresh_attempt = 1000.0

    # Setup responses: Only enough for ONE success
    mock_client.get.side_effect = [
        Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
        Mock(status_code=200, json=lambda: {"keys": ["fresh_parallel"]}),
        # If any other call gets through, it would fail or use next mock
    ]

    async def delayed_fetch(force: bool) -> Dict[str, Any]:
        # Explicit assignment to typed variable to satisfy both strict mypy envs (no-any-return)
        # and envs where inference works (avoiding redundant-cast)
        result: Dict[str, Any] = await provider.get_jwks(force_refresh=force)
        return result

    # Launch 5 concurrent requests
    # We use a custom sleep in the mock to ensure they overlap
    # But for this test, we rely on the Lock.

    # We need to ensure that when they hit the lock, they serialize.
    # The first one updates _last_refresh_attempt.
    # The subsequent ones check the condition inside the lock and see the fresh timestamp.

    # We patch time globally for the duration of the concurrent calls
    # to avoid race conditions with unpatching in interleaved tasks.
    with patch("time.time", return_value=2000.0):  # Long after 1000.0
        results = await asyncio.gather(
            delayed_fetch(True),
            delayed_fetch(True),
            delayed_fetch(True),
            delayed_fetch(True),
            delayed_fetch(True),
        )

    # All should return the fresh key
    for res in results:
        assert res == {"keys": ["fresh_parallel"]}

    # Crucial: Client should be called only ONCE (config + keys)
    assert mock_client.get.call_count == 2
