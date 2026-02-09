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
from typing import Any

import anyio
import httpx
from pydantic import ValidationError

from coreason_identity.exceptions import CoreasonIdentityError, OversizedResponseError
from coreason_identity.models_internal import OIDCConfig
from coreason_identity.transport import SafeAsyncTransport, safe_json_fetch
from coreason_identity.utils.logger import logger


class OIDCProvider:
    """
    Fetches and caches the Identity Provider's configuration and JWKS.

    Attributes:
        discovery_url (str): The OIDC discovery URL.
        cache_ttl (int): The cache time-to-live in seconds.
    """

    def __init__(
        self,
        discovery_url: str,
        client: httpx.AsyncClient,
        cache_ttl: int = 3600,
        refresh_cooldown: float = 30.0,
    ) -> None:
        """
        Initialize the OIDCProvider.

        Args:
            discovery_url: The OIDC discovery URL (e.g., https://my-tenant.auth0.com/.well-known/openid-configuration).
            client: The async HTTP client to use for requests.
            cache_ttl: Time-to-live for the JWKS cache in seconds. Defaults to 3600 (1 hour).
            refresh_cooldown: Minimum time in seconds between forced refreshes. Defaults to 30.0.
        """
        self.discovery_url = discovery_url
        self.client = client
        self.cache_ttl = cache_ttl
        self.refresh_cooldown = refresh_cooldown
        self._jwks_cache: dict[str, Any] | None = None
        self._oidc_config_cache: OIDCConfig | None = None
        self._last_update: float = 0.0
        self._lock: anyio.Lock | None = None

    async def _fetch_oidc_config(self) -> OIDCConfig:
        """
        Fetches the OIDC configuration to find the jwks_uri.

        Retries on `httpx.HTTPError` up to 3 times with exponential backoff (initial=0.1s, max=1.0s).

        Uses manual HTTP (Authlib AsyncOAuth2Client has limited metadata support) but strict Pydantic validation.

        Returns:
            OIDCConfig: The OIDC configuration object.

        Raises:
            CoreasonIdentityError: If the request fails after retries or returns invalid data.
        """
        attempts = 3
        wait_initial = 0.1
        wait_max = 1.0

        # Use a transient safe client to ensure SSRF protection and avoid resource leaks
        async with httpx.AsyncClient(
            transport=SafeAsyncTransport(), timeout=self.client.timeout
        ) as safe_client:
            for attempt in range(attempts):
                try:
                    data = await safe_json_fetch(safe_client, self.discovery_url)
                    return OIDCConfig(**data)
                except (CoreasonIdentityError, httpx.HTTPError) as e:
                    # Do not retry fatal errors like OversizedResponseError (if wrapped) or Validation
                    if isinstance(e, (OversizedResponseError, ValidationError)):
                        raise

                    # If it's the last attempt, wrap and raise
                    if attempt == attempts - 1:
                        raise CoreasonIdentityError(
                            f"Failed to fetch OIDC configuration from {self.discovery_url}: {e}"
                        ) from e

                    sleep_time = min(wait_initial * (2 ** attempt), wait_max)
                    await anyio.sleep(sleep_time)
                except ValidationError as e:
                    # Validation error is fatal, do not retry
                    raise CoreasonIdentityError(f"Invalid OIDC configuration from {self.discovery_url}: {e}") from e

        # Helper for mypy mostly, unreachable given loop structure
        raise CoreasonIdentityError(f"Failed to fetch OIDC configuration from {self.discovery_url}")  # pragma: no cover

    async def _fetch_jwks(self, jwks_uri: str) -> dict[str, Any]:
        """
        Fetches the JWKS from the given URI.

        Retries on `httpx.HTTPError` up to 3 times with exponential backoff (initial=0.1s, max=1.0s).

        Args:
            jwks_uri: The URI to fetch JWKS from.

        Returns:
            dict[str, Any]: The JWKS dictionary.

        Raises:
            CoreasonIdentityError: If the request fails after retries.
        """
        attempts = 3
        wait_initial = 0.1
        wait_max = 1.0

        # Use a transient safe client to ensure SSRF protection and avoid resource leaks
        async with httpx.AsyncClient(
            transport=SafeAsyncTransport(), timeout=self.client.timeout
        ) as safe_client:
            for attempt in range(attempts):
                try:
                    return await safe_json_fetch(safe_client, jwks_uri)  # type: ignore[no-any-return]
                except (CoreasonIdentityError, httpx.HTTPError) as e:
                    # Do not retry fatal errors
                    if isinstance(e, OversizedResponseError):
                        raise

                    if attempt == attempts - 1:
                        raise CoreasonIdentityError(f"Failed to fetch JWKS from {jwks_uri}: {e}") from e

                    sleep_time = min(wait_initial * (2 ** attempt), wait_max)
                    await anyio.sleep(sleep_time)

        raise CoreasonIdentityError(f"Failed to fetch JWKS from {jwks_uri}")  # pragma: no cover

    async def _refresh_jwks_critical_section(self, force_refresh: bool) -> dict[str, Any]:
        """
        Critical section for refreshing JWKS.
        Must be called while holding the lock.
        """
        current_time = time.time()

        # Check existing cache validity (Double check inside lock)
        is_cache_valid = self._jwks_cache is not None and (current_time - self._last_update) < self.cache_ttl

        # Check DoS protection cooldown
        is_in_cooldown = self._jwks_cache is not None and (current_time - self._last_update) < self.refresh_cooldown

        # 1. Normal cache hit (no force refresh)
        if not force_refresh and is_cache_valid:
            return self._jwks_cache  # type: ignore[return-value]

        # 2. DoS Protection: If force_refresh is requested but we are in cooldown, return cached data
        if force_refresh and is_in_cooldown:
            logger.warning("JWKS refresh cooldown active. Returning cached keys despite force_refresh request.")
            return self._jwks_cache  # type: ignore[return-value]

        # Fetch fresh keys
        oidc_config = await self._fetch_oidc_config()
        jwks_uri = oidc_config.jwks_uri

        jwks = await self._fetch_jwks(jwks_uri)

        # Update cache
        self._jwks_cache = jwks
        self._oidc_config_cache = oidc_config
        self._last_update = current_time

        return jwks  # type: ignore[no-any-return, unused-ignore]

    async def get_jwks(self, force_refresh: bool = False) -> dict[str, Any]:
        """
        Returns the JWKS, using the cache if valid.

        Args:
            force_refresh: If True, bypasses the cache and fetches fresh keys.

        Returns:
            dict[str, Any]: The JWKS dictionary.

        Raises:
            CoreasonIdentityError: If fetching fails.
        """
        if self._lock is None:
            self._lock = anyio.Lock()

        # Double-checked locking pattern optimization (Check 1: No lock)
        if not force_refresh:
            current_time = time.time()
            if self._jwks_cache is not None and (current_time - self._last_update) < self.cache_ttl:
                return self._jwks_cache

        async with self._lock:
            return await self._refresh_jwks_critical_section(force_refresh)

    async def get_issuer(self) -> str:
        """
        Returns the issuer from the OIDC configuration.
        Refreshes configuration if not cached or expired (via get_jwks).

        Returns:
            str: The issuer string.

        Raises:
            CoreasonIdentityError: If configuration is invalid or fetching fails.
        """
        # Ensure cache is populated
        if self._oidc_config_cache is None or (time.time() - self._last_update) >= self.cache_ttl:
            await self.get_jwks()

        if self._oidc_config_cache is None:
            # Should be unreachable if get_jwks succeeds
            raise CoreasonIdentityError("Failed to load OIDC configuration")

        return self._oidc_config_cache.issuer
