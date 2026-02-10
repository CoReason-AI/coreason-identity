# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

"""
Tests for OIDCProvider coverage.
"""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from coreason_identity.exceptions import CoreasonIdentityError, OversizedResponseError
from coreason_identity.oidc_provider import OIDCProvider


@pytest.fixture
def mock_client() -> AsyncMock:
    return AsyncMock(spec=httpx.AsyncClient)


class TestOIDCProviderCoverage:
    @pytest.mark.asyncio
    async def test_fetch_oidc_config_oversized(self, mock_client: AsyncMock) -> None:
        """Test line 89: OversizedResponseError in _fetch_oidc_config."""
        provider = OIDCProvider("https://idp", mock_client)

        # Mock safe_json_fetch to raise OversizedResponseError
        with patch("coreason_identity.oidc_provider.safe_json_fetch", side_effect=OversizedResponseError("Too big")):
            with pytest.raises(OversizedResponseError):
                await provider._fetch_oidc_config()

    @pytest.mark.asyncio
    async def test_fetch_jwks_oversized(self, mock_client: AsyncMock) -> None:
        """Test line 133: OversizedResponseError in _fetch_jwks."""
        provider = OIDCProvider("https://idp", mock_client)

        with patch("coreason_identity.oidc_provider.safe_json_fetch", side_effect=OversizedResponseError("Too big")):
            with pytest.raises(OversizedResponseError):
                await provider._fetch_jwks("uri")

    @pytest.mark.asyncio
    async def test_refresh_jwks_critical_section_no_force_valid_cache(self, mock_client: AsyncMock) -> None:
        """Test lines 162-163: Valid cache check inside critical section."""
        provider = OIDCProvider("https://idp", mock_client)

        # Manually set cache
        import time
        provider._jwks_cache = {"keys": []}
        provider._last_update = time.time()

        # Call private method directly to verify logic
        # force_refresh=False, cache valid -> should return cache
        jwks = await provider._refresh_jwks_critical_section(force_refresh=False)
        assert jwks == {"keys": []}

        # Ensure it didn't fetch
        # We can check by mocking _fetch_oidc_config and asserting not called
        with patch.object(provider, "_fetch_oidc_config") as mock_fetch:
            await provider._refresh_jwks_critical_section(force_refresh=False)
            mock_fetch.assert_not_called()
