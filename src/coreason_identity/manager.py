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

from typing import Optional
from urllib.parse import urljoin

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.models import DeviceFlowResponse, TokenResponse, UserContext
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class IdentityManager:
    """
    Main entry point for coreason-identity.
    Orchestrates OIDCProvider, TokenValidator, IdentityMapper, and DeviceFlowClient.
    """

    def __init__(self, config: CoreasonIdentityConfig) -> None:
        """
        Initialize the IdentityManager.

        Args:
            config: The configuration object.
        """
        self.config = config

        # Domain is already normalized by Config validator to be just the hostname (e.g. auth.coreason.com)
        self.domain = self.config.domain

        # Construct base URL (must start with https:// for OIDC)
        base_url = f"https://{self.domain}"

        # Use urljoin for robust path construction
        # Note: urljoin("https://host", "/path") -> "https://host/path"
        discovery_url = urljoin(base_url, "/.well-known/openid-configuration")
        issuer_url = urljoin(base_url, "/")

        self.oidc_provider = OIDCProvider(discovery_url)
        self.validator = TokenValidator(
            oidc_provider=self.oidc_provider,
            audience=self.config.audience,
            issuer=issuer_url,
        )
        self.identity_mapper = IdentityMapper()
        self.device_client: Optional[DeviceFlowClient] = None

    def validate_token(self, auth_header: str) -> UserContext:
        """
        Validates the Bearer token and returns the UserContext.

        Args:
            auth_header: The Authorization header string (e.g., "Bearer <token>").

        Returns:
            The UserContext object.

        Raises:
            InvalidTokenError: If the token is invalid, expired, or malformed.
        """
        if not auth_header or not auth_header.startswith("Bearer "):
            raise InvalidTokenError("Missing or invalid Authorization header format. Must start with 'Bearer '.")

        token = auth_header[7:]  # Strip "Bearer "

        # Delegate to TokenValidator
        # It raises specific exceptions like TokenExpiredError, which inherit from InvalidTokenError
        claims = self.validator.validate_token(token)

        # Delegate to IdentityMapper
        return self.identity_mapper.map_claims(claims)

    def start_device_login(self, scope: Optional[str] = None) -> DeviceFlowResponse:
        """
        Initiates the Device Authorization Flow.

        Args:
            scope: Optional scope override.

        Returns:
            DeviceFlowResponse containing the verification URI and user code.

        Raises:
            CoreasonIdentityError: If client_id is not configured or flow fails.
        """
        if not self.config.client_id:
            raise CoreasonIdentityError("client_id is required for device login but not configured.")

        # Initialize DeviceFlowClient on demand
        if not self.device_client:
            self.device_client = DeviceFlowClient(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
                scope=scope or "openid profile email",
            )
        else:
            self.device_client = DeviceFlowClient(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
                scope=scope or "openid profile email",
            )

        return self.device_client.initiate_flow(audience=self.config.audience)

    def await_device_token(self, flow: DeviceFlowResponse) -> TokenResponse:
        """
        Polls for the device token.

        Args:
            flow: The response from start_device_login.

        Returns:
            The TokenResponse containing the tokens.

        Raises:
            CoreasonIdentityError: If client_id is not configured or polling fails.
        """
        if not self.config.client_id:
            raise CoreasonIdentityError("client_id is required for device login but not configured.")

        if not self.device_client:
            self.device_client = DeviceFlowClient(
                client_id=self.config.client_id,
                idp_url=f"https://{self.domain}",
            )

        return self.device_client.poll_token(flow)
