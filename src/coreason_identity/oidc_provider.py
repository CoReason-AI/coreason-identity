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

import time
from typing import Any, Dict, Optional

import anyio
import httpx
from anyio.from_thread import start_blocking_portal

from coreason_identity.exceptions import CoreasonIdentityError


class OIDCProviderAsync:
    """
    Fetches and caches the Identity Provider's configuration and JWKS (Async).
    """

    def __init__(
        self,
        discovery_url: str,
        cache_ttl: float = 3600,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        """
        Initialize the OIDCProviderAsync.

        Args:
            discovery_url: The OIDC discovery URL.
            cache_ttl: Time-to-live for the JWKS cache in seconds.
            client: Optional external httpx.AsyncClient.
        """
        self.discovery_url = discovery_url
        self.cache_ttl = cache_ttl
        self._jwks_cache: Optional[Dict[str, Any]] = None
        self._last_update: float = 0.0

        # Client management
        self._internal_client = client is None
        self._client = client

        # Lock will be initialized in __aenter__ to ensure it's bound to the correct loop
        self._lock: Optional[anyio.Lock] = None

    async def __aenter__(self) -> "OIDCProviderAsync":
        if self._client is None:
            self._client = httpx.AsyncClient()
        if self._lock is None:
            self._lock = anyio.Lock()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._internal_client and self._client:
            await self._client.aclose()
        # We don't necessarily destroy the lock here, but if we re-enter on a new loop,
        # we need a new lock. Setting to None ensures checking in __aenter__.
        self._lock = None

    async def _fetch_oidc_config(self) -> Dict[str, Any]:
        """Fetches the OIDC configuration."""
        if not self._client:
            raise CoreasonIdentityError("Client not initialized. Use 'async with' context manager.")

        try:
            response = await self._client.get(self.discovery_url)
            response.raise_for_status()
            return response.json()  # type: ignore[no-any-return]
        except httpx.HTTPError as e:
            raise CoreasonIdentityError(f"Failed to fetch OIDC configuration from {self.discovery_url}: {e}") from e

    async def _fetch_jwks(self, jwks_uri: str) -> Dict[str, Any]:
        """Fetches the JWKS from the given URI."""
        if not self._client:
            raise CoreasonIdentityError("Client not initialized. Use 'async with' context manager.")

        try:
            response = await self._client.get(jwks_uri)
            response.raise_for_status()
            return response.json()  # type: ignore[no-any-return]
        except httpx.HTTPError as e:
            raise CoreasonIdentityError(f"Failed to fetch JWKS from {jwks_uri}: {e}") from e

    async def get_jwks(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Returns the JWKS, using the cache if valid.
        """
        # Double-checked locking pattern
        if not force_refresh:
            current_time = time.time()
            if self._jwks_cache is not None and (current_time - self._last_update) < self.cache_ttl:
                return self._jwks_cache

        if self._lock is None:
            raise CoreasonIdentityError("Lock not initialized. Use 'async with' context manager.")

        async with self._lock:
            # Check again inside lock
            current_time = time.time()
            if (
                not force_refresh
                and self._jwks_cache is not None
                and (current_time - self._last_update) < self.cache_ttl
            ):
                return self._jwks_cache

            # Fetch fresh keys
            oidc_config = await self._fetch_oidc_config()
            jwks_uri = oidc_config.get("jwks_uri")
            if not jwks_uri:
                raise CoreasonIdentityError("OIDC configuration does not contain 'jwks_uri'")

            jwks = await self._fetch_jwks(jwks_uri)

            # Update cache
            self._jwks_cache = jwks
            self._last_update = current_time

            return jwks


class OIDCProvider:
    """
    Sync Facade for OIDCProviderAsync.
    Wraps the async core in a blocking portal for synchronous usage.
    """

    def __init__(self, discovery_url: str, cache_ttl: float = 3600) -> None:
        self._async = OIDCProviderAsync(discovery_url, cache_ttl)
        self._portal_cm: Any = None
        self._portal: Any = None

    def __enter__(self) -> "OIDCProvider":
        self._portal_cm = start_blocking_portal()
        self._portal = self._portal_cm.__enter__()
        self._portal.call(self._async.__aenter__)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            self._portal.call(self._async.__aexit__, exc_type, exc_val, exc_tb)
        finally:
            if self._portal_cm:
                self._portal_cm.__exit__(exc_type, exc_val, exc_tb)

    def get_jwks(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Returns the JWKS, using the cache if valid."""
        if not self._portal:
            raise CoreasonIdentityError("Context not started. Use 'with OIDCProvider(...):'.")
        return self._portal.call(self._async.get_jwks, force_refresh)
