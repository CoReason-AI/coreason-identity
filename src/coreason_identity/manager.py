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

import re
from typing import Any
from urllib.parse import urljoin

import anyio
import httpx

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.models import DeviceFlowResponse, TokenResponse, UserContext
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class IdentityManagerAsync:
    """
    Async implementation of IdentityManager (The Core).
    Handles resources via async context manager.
    """

    def __init__(self, config: CoreasonIdentityConfig, client: httpx.AsyncClient | None = None) -> None:
        """
        Initialize the IdentityManagerAsync.

        Args:
            config: The configuration object.
            client: External async client or None.
        """
        self.config = config
        self._internal_client = client is None
        self._client = client or httpx.AsyncClient()

        # Domain is already normalized by Config validator to be just the hostname (e.g. auth.coreason.com)
        self.domain = self.config.domain

        # Construct base URL (must start with https:// for OIDC)
        base_url = f"https://{self.domain}"

        # Use urljoin for robust path construction
        discovery_url = urljoin(base_url, "/.well-known/openid-configuration")

        self.oidc_provider = OIDCProvider(discovery_url, self._client)
        # Initialize TokenValidator with strict issuer from config
        if not self.config.issuer:
            raise CoreasonIdentityError("Issuer configuration is missing")

        self.validator = TokenValidator(
            oidc_provider=self.oidc_provider,
            audience=self.config.audience,
            pii_salt=self.config.pii_salt,
            issuer=self.config.issuer,
        )
        self.identity_mapper = IdentityMapper()
        self.device_client: DeviceFlowClient | None = None

    async def __aenter__(self) -> "IdentityManagerAsync":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._internal_client:
            await self._client.aclose()

    async def validate_token(self, auth_header: str) -> UserContext:
        """
        Validates the Bearer token and returns the UserContext.
        """
        if not auth_header:
            raise InvalidTokenError("Missing Authorization header.")

        # Strict regex validation to avoid raw string splitting
        match = re.match(r"^Bearer\s+(.+)$", auth_header)
        if not match:
            raise InvalidTokenError("Invalid Authorization header format. Must start with 'Bearer '.")

        token = match.group(1).strip()

        # Delegate to TokenValidator
        claims = await self.validator.validate_token(token)

        # Delegate to IdentityMapper
        return self.identity_mapper.map_claims(claims, token=token)

    async def start_device_login(self, scope: str | None = None) -> DeviceFlowResponse:
        """
        Initiates the Device Authorization Flow.
        """
        if not self.config.client_id:
            raise CoreasonIdentityError("client_id is required for device login but not configured.")

        if not self.device_client:
            self.device_client = DeviceFlowClient(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
                client=self._client,
                scope=scope or "openid profile email",
            )
        else:
            # Re-init if needed to ensure correct client is passed if we ever support changing it,
            # but more importantly to match the synchronous re-init logic if we want to be safe.
            # However, since we persist self.device_client and it has self._client, it should be fine.
            # But let's follow the pattern of the sync code which re-created it.
            self.device_client = DeviceFlowClient(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
                client=self._client,
                scope=scope or "openid profile email",
            )

        return await self.device_client.initiate_flow(audience=self.config.audience)

    async def await_device_token(self, flow: DeviceFlowResponse) -> TokenResponse:
        """
        Polls for the device token.
        """
        if not self.config.client_id:
            raise CoreasonIdentityError("client_id is required for device login but not configured.")

        if not self.device_client:
            self.device_client = DeviceFlowClient(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
                client=self._client,
            )

        return await self.device_client.poll_token(flow)


class IdentityManagerSync:
    """
    Synchronous facade for IdentityManagerAsync. WARNING: This class uses blocking IO.
    Wraps IdentityManagerAsync and bridges Sync -> Async via anyio.run.
    """

    def __init__(self, config: CoreasonIdentityConfig) -> None:
        """
        Initialize the IdentityManagerSync Facade.

        Args:
            config: The configuration object.
        """
        self._async = IdentityManagerAsync(config)

    def __enter__(self) -> "IdentityManagerSync":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # anyio.run expects a coroutine function or a coroutine object?
        # anyio.run(func, *args)
        # self._async.__aexit__ is a method, so we can pass it and arguments.
        # But wait, __aexit__ returns a coroutine.
        # anyio.run(self._async.__aexit__, exc_type, exc_val, exc_tb) is correct.
        anyio.run(self._async.__aexit__, exc_type, exc_val, exc_tb)

    def validate_token(self, auth_header: str) -> UserContext:
        """
        Validates the Bearer token and returns the UserContext.
        """
        return anyio.run(self._async.validate_token, auth_header)

    def start_device_login(self, scope: str | None = None) -> DeviceFlowResponse:
        """
        Initiates the Device Authorization Flow.
        """
        return anyio.run(self._async.start_device_login, scope)

    def await_device_token(self, flow: DeviceFlowResponse) -> TokenResponse:
        """
        Polls for the device token.
        """
        return anyio.run(self._async.await_device_token, flow)
