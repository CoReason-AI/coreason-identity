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
OIDC Provider component for fetching and caching JWKS.
"""

import threading
import time
from typing import Any, Dict, Optional

import httpx

from coreason_identity.exceptions import CoreasonIdentityError


class OIDCProvider:
    """
    Fetches and caches the Identity Provider's configuration and JWKS.

    Attributes:
        discovery_url (str): The OIDC discovery URL.
        cache_ttl (int): The cache time-to-live in seconds.
    """

    def __init__(self, discovery_url: str, cache_ttl: int = 3600) -> None:
        """
        Initialize the OIDCProvider.

        Args:
            discovery_url: The OIDC discovery URL (e.g., https://my-tenant.auth0.com/.well-known/openid-configuration).
            cache_ttl: Time-to-live for the JWKS cache in seconds. Defaults to 3600 (1 hour).
        """
        self.discovery_url = discovery_url
        self.cache_ttl = cache_ttl
        self._jwks_cache: Optional[Dict[str, Any]] = None
        self._last_update: float = 0.0
        self._lock = threading.Lock()

    def _fetch_oidc_config(self) -> Dict[str, Any]:
        """
        Fetches the OIDC configuration to find the jwks_uri.

        Returns:
            The OIDC configuration dictionary.

        Raises:
            CoreasonIdentityError: If the request fails or returns invalid data.
        """
        try:
            with httpx.Client() as client:
                response = client.get(self.discovery_url)
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
        except httpx.HTTPError as e:
            raise CoreasonIdentityError(f"Failed to fetch OIDC configuration from {self.discovery_url}: {e}") from e

    def _fetch_jwks(self, jwks_uri: str) -> Dict[str, Any]:
        """
        Fetches the JWKS from the given URI.

        Args:
            jwks_uri: The URI to fetch JWKS from.

        Returns:
            The JWKS dictionary.

        Raises:
            CoreasonIdentityError: If the request fails.
        """
        try:
            with httpx.Client() as client:
                response = client.get(jwks_uri)
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
        except httpx.HTTPError as e:
            raise CoreasonIdentityError(f"Failed to fetch JWKS from {jwks_uri}: {e}") from e

    def get_jwks(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Returns the JWKS, using the cache if valid.

        Args:
            force_refresh: If True, bypasses the cache and fetches fresh keys.

        Returns:
            The JWKS dictionary.

        Raises:
            CoreasonIdentityError: If fetching fails.
        """
        # Double-checked locking pattern optimization
        if not force_refresh:
            current_time = time.time()
            if self._jwks_cache is not None and (current_time - self._last_update) < self.cache_ttl:
                return self._jwks_cache

        with self._lock:
            # Check again inside lock
            current_time = time.time()
            if (
                not force_refresh
                and self._jwks_cache is not None
                and (current_time - self._last_update) < self.cache_ttl
            ):
                return self._jwks_cache  # pragma: no cover

            # Fetch fresh keys
            oidc_config = self._fetch_oidc_config()
            jwks_uri = oidc_config.get("jwks_uri")
            if not jwks_uri:
                raise CoreasonIdentityError("OIDC configuration does not contain 'jwks_uri'")

            jwks = self._fetch_jwks(jwks_uri)

            # Update cache
            self._jwks_cache = jwks
            self._last_update = current_time

            return jwks
