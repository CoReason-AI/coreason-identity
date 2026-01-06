# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import threading
import time
from unittest.mock import Mock, patch

from coreason_identity.oidc_provider import OIDCProvider


class TestOIDCProviderConcurrency:
    @patch("httpx.Client")
    def test_get_jwks_concurrency(self, mock_httpx: Mock) -> None:
        """
        Test that multiple concurrent calls to get_jwks trigger only one fetch
        due to locking and caching.
        """
        provider = OIDCProvider("https://idp/.well-known/openid-configuration")

        # Setup mocks
        mock_http = mock_httpx.return_value.__enter__.return_value

        # Mock OIDC Config response
        # To handle multiple threads calling this, we need to ensure the side_effect
        # doesn't run out if the lock fails (which it shouldn't).
        # But correctly, it should only be called once.
        mock_http.get.side_effect = [
            Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
            Mock(status_code=200, json=lambda: {"keys": []}),  # JWKS response
        ]

        # Define a function to be run in threads
        results = []

        def worker() -> None:
            jwks = provider.get_jwks()
            results.append(jwks)

        # Create threads
        threads = [threading.Thread(target=worker) for _ in range(10)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # Verify results
        assert len(results) == 10
        # Should have only fetched config once and JWKS once (2 GET calls total)
        assert mock_http.get.call_count == 2

    def test_double_checked_locking_manual(self) -> None:
        """
        Manually verify the logic flow of double-checked locking without threads.
        """
        provider = OIDCProvider("url")
        provider._jwks_cache = {"keys": []}
        provider._last_update = time.time()

        # Should return cached without lock
        with patch.object(provider, "_fetch_oidc_config") as mock_fetch:
            provider.get_jwks()
            mock_fetch.assert_not_called()

        # Force refresh
        with (
            patch.object(provider, "_fetch_oidc_config") as mock_fetch,
            patch.object(provider, "_fetch_jwks") as mock_jwks,
        ):
            mock_fetch.return_value = {"jwks_uri": "uri"}
            mock_jwks.return_value = {"keys": ["new"]}

            jwks = provider.get_jwks(force_refresh=True)

            assert jwks == {"keys": ["new"]}
            mock_fetch.assert_called_once()
            mock_jwks.assert_called_once()
