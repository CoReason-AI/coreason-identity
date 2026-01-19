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
IdentityManager component for orchestrating authentication and authorization.
"""

from typing import Any, Optional
from urllib.parse import urljoin

import anyio
import httpx
from anyio.from_thread import start_blocking_portal

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.device_flow_client import DeviceFlowClientAsync
from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.models import DeviceFlowResponse, TokenResponse, UserContext
from coreason_identity.oidc_provider import OIDCProviderAsync
from coreason_identity.validator import TokenValidatorAsync


class IdentityManagerAsync:
    """
    Main entry point for coreason-identity (Async).
    Orchestrates OIDCProvider, TokenValidator, IdentityMapper, and DeviceFlowClient.
    """

    def __init__(
        self,
        config: CoreasonIdentityConfig,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        """
        Initialize the IdentityManagerAsync.

        Args:
            config: The configuration object.
            client: Optional external httpx.AsyncClient.
        """
        self.config = config
        self.domain = self.config.domain

        # Manage client
        self._internal_client = client is None
        self._client = client or httpx.AsyncClient()

        # Construct base URL (must start with https:// for OIDC)
        base_url = f"https://{self.domain}"

        # Use urljoin for robust path construction
        discovery_url = urljoin(base_url, "/.well-known/openid-configuration")
        issuer_url = urljoin(base_url, "/")

        # Initialize OIDCProvider with shared client
        self.oidc_provider = OIDCProviderAsync(discovery_url, client=self._client)

        # Initialize TokenValidator with OIDCProvider
        self.validator = TokenValidatorAsync(
            oidc_provider=self.oidc_provider,
            audience=self.config.audience,
            issuer=issuer_url,
        )

        self.identity_mapper = IdentityMapper()
        self.device_client: Optional[DeviceFlowClientAsync] = None

    async def __aenter__(self) -> "IdentityManagerAsync":
        # Ensure client is ready (already created in init, but could be closed?)
        if self._client.is_closed:
            # If closed, and we own it, we might need to recreate?
            # Or assume user manages it.
            # If we own it, we should ensure it's open? httpx.AsyncClient isn't easily re-opened.
            pass

        # Enter children to initialize their loop-bound resources (like locks)
        await self.oidc_provider.__aenter__()

        if self.device_client:
            await self.device_client.__aenter__()

        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # Exit children
        await self.oidc_provider.__aexit__(exc_type, exc_val, exc_tb)

        if self.device_client:
            await self.device_client.__aexit__(exc_type, exc_val, exc_tb)

        # Close client if we own it
        if self._internal_client:
            await self._client.aclose()

    async def validate_token(self, auth_header: str) -> UserContext:
        """
        Validates the Bearer token and returns the UserContext.
        """
        if not auth_header or not auth_header.startswith("Bearer "):
            raise InvalidTokenError("Missing or invalid Authorization header format. Must start with 'Bearer '.")

        token = auth_header[7:]  # Strip "Bearer "

        # Delegate to TokenValidator
        claims = await self.validator.validate_token(token)

        # Delegate to IdentityMapper
        return self.identity_mapper.map_claims(claims)

    async def start_device_login(self, scope: Optional[str] = None) -> DeviceFlowResponse:
        """
        Initiates the Device Authorization Flow.
        """
        if not self.config.client_id:
            raise CoreasonIdentityError("client_id is required for device login but not configured.")

        # Initialize DeviceFlowClient on demand with shared client
        if not self.device_client:
            self.device_client = DeviceFlowClientAsync(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
                scope=scope or "openid profile email",
                client=self._client,
            )
            # Must enter it to bind resources
            await self.device_client.__aenter__()
        else:
             # If reusing, ensure props are updated if needed, but usually strictly init once.
             # If scope changes? DeviceFlowClientAsync stores scope.
             # We recreate if needed? For now assume one client per manager usage.
             pass

        return await self.device_client.initiate_flow(audience=self.config.audience)

    async def await_device_token(self, flow: DeviceFlowResponse) -> TokenResponse:
        """
        Polls for the device token.
        """
        if not self.config.client_id:
            raise CoreasonIdentityError("client_id is required for device login but not configured.")

        if not self.device_client:
            self.device_client = DeviceFlowClientAsync(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
                client=self._client,
            )
            await self.device_client.__aenter__()

        return await self.device_client.poll_token(flow)


class IdentityManager:
    """
    Sync Facade for IdentityManagerAsync.
    """

    def __init__(self, config: CoreasonIdentityConfig) -> None:
        self._async = IdentityManagerAsync(config)
        self._portal_cm: Any = None
        self._portal: Any = None

    def __enter__(self) -> "IdentityManager":
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

    def validate_token(self, auth_header: str) -> UserContext:
        if not self._portal:
             raise CoreasonIdentityError("Context not started. Use 'with IdentityManager(...):'.")
        return self._portal.call(self._async.validate_token, auth_header)

    def start_device_login(self, scope: Optional[str] = None) -> DeviceFlowResponse:
        if not self._portal:
             raise CoreasonIdentityError("Context not started. Use 'with IdentityManager(...):'.")
        return self._portal.call(self._async.start_device_login, scope)

    def await_device_token(self, flow: DeviceFlowResponse) -> TokenResponse:
        if not self._portal:
             raise CoreasonIdentityError("Context not started. Use 'with IdentityManager(...):'.")
        return self._portal.call(self._async.await_device_token, flow)
