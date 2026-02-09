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

import httpx
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

from coreason_identity.config import CoreasonClientConfig, CoreasonVerifierConfig
from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.models import DeviceFlowResponse, TokenResponse, UserContext
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.transport import SafeHTTPTransport
from coreason_identity.validator import TokenValidator


class IdentityManager:
    """
    Async implementation of IdentityManager (The Core).
    Handles resources via async context manager.
    """

    def __init__(self, config: CoreasonVerifierConfig, client: httpx.AsyncClient | None = None) -> None:
        """
        Initialize the IdentityManager.

        Args:
            config: The configuration object.
            client: External async client (optional). If not provided, a `SafeHTTPTransport` client is created.
        """
        self.config = config
        self._internal_client = client is None

        if client:
            self._client = client
        else:
            # Use SafeHTTPTransport to prevent SSRF and DNS Rebinding
            transport = SafeHTTPTransport()
            self._client = httpx.AsyncClient(transport=transport, timeout=self.config.http_timeout)

        # Instrument the client for distributed tracing
        HTTPXClientInstrumentor().instrument_client(self._client)

        # Domain is already normalized by Config validator to be just the hostname (e.g. auth.coreason.com)
        self.domain = self.config.domain

        # Construct base URL (must start with https:// for OIDC)
        base_url = f"https://{self.domain}"

        # Use urljoin for robust path construction
        discovery_url = urljoin(base_url, "/.well-known/openid-configuration")

        self.oidc_provider = OIDCProvider(discovery_url, self._client)

        # Initialize TokenValidator with strict issuer from config
        # Pydantic validator guarantees issuer is populated, but we assert for MyPy
        if self.config.issuer is None:
            raise CoreasonIdentityError("Issuer configuration is missing")

        self.validator = TokenValidator(
            oidc_provider=self.oidc_provider,
            audience=self.config.audience,
            pii_salt=self.config.pii_salt,
            issuer=self.config.issuer,
            allowed_algorithms=self.config.allowed_algorithms,
            leeway=self.config.clock_skew_leeway,
        )
        self.identity_mapper = IdentityMapper()
        self.device_client: DeviceFlowClient | None = None

    async def __aenter__(self) -> "IdentityManager":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._internal_client:
            await self._client.aclose()

    async def validate_token(self, auth_header: str) -> UserContext:
        """
        Validates the Bearer token and returns the UserContext.

        Delegates validation to `TokenValidator.validate_token` and mapping to `IdentityMapper`.

        Args:
            auth_header: The raw 'Authorization' header value (e.g., "Bearer <token>").

        Returns:
            UserContext: The validated user context containing identity and RBAC information.

        Raises:
            InvalidTokenError: If the header is malformed, missing, or the token is invalid.
            TokenExpiredError: If the token has expired.
            InvalidAudienceError: If the token audience does not match the configuration.
            SignatureVerificationError: If the token signature is invalid.
            CoreasonIdentityError: For underlying network or configuration errors.
        """
        if not auth_header:
            raise InvalidTokenError("Missing Authorization header.")

        # Strict regex validation to avoid raw string splitting
        # Disallow spaces/garbage in the token part
        match = re.match(r"^Bearer\s+(\S+)$", auth_header)
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

        Uses `DeviceFlowClient` to communicate with the IdP.

        Args:
            scope: The OAuth2 scopes to request (e.g., "openid profile"). Must be explicitly provided.

        Returns:
            DeviceFlowResponse: The response containing the device code, user code, and verification URI.

        Raises:
            CoreasonIdentityError: If the configuration is invalid (missing client_id) or the IdP request fails.
            ValueError: If the scope is missing or empty.
        """
        if not isinstance(self.config, CoreasonClientConfig):
            raise CoreasonIdentityError("Device login requires CoreasonClientConfig with a valid client_id.")

        if not scope or not scope.strip():
            raise ValueError("Scope must be explicitly provided (e.g., 'openid profile').")

        if not self.device_client:
            self.device_client = DeviceFlowClient(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
                client=self._client,
                scope=scope,
            )
        else:
            # Re-init if needed to ensure correct client is passed
            self.device_client = DeviceFlowClient(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
                client=self._client,
                scope=scope,
            )

        return await self.device_client.initiate_flow(audience=self.config.audience)

    async def await_device_token(self, flow: DeviceFlowResponse) -> TokenResponse:
        """
        Polls for the device token.

        Polls the IdP token endpoint until the user authorizes the device, the code expires, or the polling times out.

        Args:
            flow: The `DeviceFlowResponse` object returned by `start_device_login`.

        Returns:
            TokenResponse: The response containing the access token and other artifacts.

        Raises:
            CoreasonIdentityError: If polling fails, the code expires, or access is denied.
        """
        if not isinstance(self.config, CoreasonClientConfig):
            raise CoreasonIdentityError("Device login requires CoreasonClientConfig with a valid client_id.")

        if not self.device_client:
            self.device_client = DeviceFlowClient(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
                client=self._client,
                scope="",  # Scope is not used during polling
            )

        return await self.device_client.poll_token(flow)
