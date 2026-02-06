# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import anyio
import pytest
from unittest.mock import AsyncMock, Mock
import httpx
from coreason_identity.oidc_provider import OIDCProvider

@pytest.fixture
def mock_client() -> AsyncMock:
    client = AsyncMock(spec=httpx.AsyncClient)
    # Setup default response for get_jwks to avoid actual network calls or crashes
    client.get.return_value = Mock(
        status_code=200,
        json=lambda: {"jwks_uri": "https://idp/jwks", "keys": []}
    )
    return client

def test_sync_init_async_run(mock_client: AsyncMock) -> None:
    # 1. Instantiate in Sync Context
    # This simulates IdentityManager.__init__ running in sync code
    provider = OIDCProvider("https://idp", mock_client)

    # 2. Define async function that uses the provider
    async def run_check() -> None:
        # Should NOT raise RuntimeError
        # We need to mock the responses so it doesn't fail on network
        mock_client.get.side_effect = [
            Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
            Mock(status_code=200, json=lambda: {"keys": []}),
        ]
        await provider.get_jwks()

    # 3. Run inside a NEW loop
    anyio.run(run_check)
