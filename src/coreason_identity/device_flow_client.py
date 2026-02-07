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
DeviceFlowClient component for handling OAuth 2.0 Device Authorization Grant.
"""

import time
from urllib.parse import urljoin

import anyio
import httpx
from pydantic import ValidationError

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import DeviceFlowResponse, TokenResponse
from coreason_identity.models_internal import OIDCConfig
from coreason_identity.utils.logger import logger


class DeviceFlowClient:
    """
    Handles the OAuth 2.0 Device Authorization Grant flow (RFC 8628).

    Attributes:
        client_id (str): The OIDC Client ID.
        idp_url (str): The base URL of the Identity Provider.
        scope (str): The scopes to request.
    """

    def __init__(
        self,
        client_id: str,
        idp_url: str,
        client: httpx.AsyncClient,
        scope: str = "openid profile email",
        min_poll_interval: float = 5.0,
        max_poll_duration: float = 900.0,
    ) -> None:
        """
        Initialize the DeviceFlowClient.

        Args:
            client_id: The OIDC Client ID.
            idp_url: The base URL of the Identity Provider (e.g., https://my-tenant.auth0.com).
            client: The async HTTP client to use for requests.
            scope: The scopes to request (default: "openid profile email").
            min_poll_interval: Minimum seconds to wait between requests (default: 5.0).
            max_poll_duration: Maximum seconds to poll before giving up (default: 900.0).
        """
        self.client_id = client_id
        self.idp_url = idp_url.rstrip("/")
        self.client = client
        self.scope = scope
        self.min_poll_interval = min_poll_interval
        self.max_poll_duration = max_poll_duration
        self._endpoints: dict[str, str] | None = None

    async def _get_endpoints(self) -> dict[str, str]:
        """
        Discover OIDC endpoints from the IdP.

        Returns:
            A dictionary containing the discovered endpoints.

        Raises:
            CoreasonIdentityError: If OIDC discovery fails.
        """
        if self._endpoints:
            return self._endpoints

        discovery_url = f"{self.idp_url}/.well-known/openid-configuration"

        try:
            response = await self.client.get(discovery_url)
            response.raise_for_status()
            try:
                # Use strict Pydantic model but allow flexible fallback for optional fields
                # We interpret the response as OIDCConfig. If it fails validation (e.g. missing issuer),
                # we wrap it.
                config = OIDCConfig(**response.json())
            except (ValueError, ValidationError) as e:
                raise CoreasonIdentityError(f"Invalid JSON response from OIDC discovery: {e}") from e

            # Fallback to standard Auth0 paths if not in config
            device_endpoint = config.device_authorization_endpoint or urljoin(f"{self.idp_url}/", "oauth/device/code")
            token_endpoint = config.token_endpoint or urljoin(f"{self.idp_url}/", "oauth/token")

            self._endpoints = {
                "device_authorization_endpoint": device_endpoint,
                "token_endpoint": token_endpoint,
            }
            return self._endpoints
        except httpx.HTTPError as e:
            raise CoreasonIdentityError(f"Failed to discover OIDC endpoints: {e}") from e

    async def initiate_flow(self, audience: str | None = None) -> DeviceFlowResponse:
        """
        Initiates the Device Authorization Flow.

        Args:
            audience: Audience for the token or None.

        Returns:
            DeviceFlowResponse containing device_code, user_code, verification_uri, etc.

        Raises:
            CoreasonIdentityError: If the flow initiation fails or the response is invalid.
        """
        endpoints = await self._get_endpoints()
        url = endpoints["device_authorization_endpoint"]

        data = {
            "client_id": self.client_id,
            "scope": self.scope,
        }
        if audience:
            data["audience"] = audience

        try:
            response = await self.client.post(url, data=data)
            response.raise_for_status()
            try:
                resp_data = response.json()
            except ValueError as e:
                raise CoreasonIdentityError(f"Invalid JSON response from initiate flow: {e}") from e
            return DeviceFlowResponse(**resp_data)
        except httpx.HTTPError as e:
            logger.error(f"Device flow initiation failed: {e}")
            raise CoreasonIdentityError(f"Failed to initiate device flow: {e}") from e
        except ValidationError as e:
            logger.error(f"Invalid response from device flow init: {e}")
            raise CoreasonIdentityError(f"Invalid response from IdP: {e}") from e

    async def poll_token(self, device_response: DeviceFlowResponse) -> TokenResponse:
        """
        Polls the token endpoint until the user authorizes the device or the code expires.

        Args:
            device_response: The response from initiate_flow.

        Returns:
            TokenResponse containing access_token, refresh_token, etc.

        Raises:
            CoreasonIdentityError: If polling fails, times out, or the request is denied.
        """
        endpoints = await self._get_endpoints()
        url = endpoints["token_endpoint"]
        device_code = device_response.device_code
        interval = device_response.interval
        expires_in = device_response.expires_in

        start_time = time.time()
        end_time = start_time + expires_in
        safety_end_time = start_time + self.max_poll_duration

        logger.info(f"Polling for token. Expires in {expires_in}s. Interval: {interval}s")

        while time.time() < min(end_time, safety_end_time):
            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": self.client_id,
            }

            try:
                response = await self.client.post(url, data=data)

                if response.status_code == 200:
                    try:
                        logger.info("Token retrieved successfully.")
                        return TokenResponse(**response.json())
                    except ValidationError as e:
                        raise CoreasonIdentityError(f"Received invalid token response structure: {e}") from e
                    except ValueError as e:
                        raise CoreasonIdentityError(f"Received invalid JSON response on 200 OK: {e}") from e

                # Handle errors
                try:
                    error_resp = response.json()
                except ValueError as e:
                    # Non-JSON response, likely a server error or proxy issue
                    response.raise_for_status()
                    raise CoreasonIdentityError(f"Received invalid response: {response.text}") from e

                if not isinstance(error_resp, dict):
                    raise CoreasonIdentityError(f"Received invalid JSON response: {error_resp}")

                error = error_resp.get("error")

                if error == "authorization_pending":
                    pass  # Continue polling
                elif error == "slow_down":
                    interval += 5  # Increase interval as per spec
                    logger.debug("Received slow_down, increasing interval.")
                elif error == "expired_token":
                    raise CoreasonIdentityError("Device code expired.")
                elif error == "access_denied":
                    raise CoreasonIdentityError("User denied access.")
                else:
                    response.raise_for_status()  # Raise for other 4xx/5xx

            except httpx.HTTPStatusError as e:
                logger.error(f"Polling failed with status {e.response.status_code}: {e}")
                raise CoreasonIdentityError(f"Polling failed: {e}") from e

            except Exception as e:
                if isinstance(e, CoreasonIdentityError):
                    raise
                logger.warning(f"Polling attempt failed: {e}")
                # Continue polling unless it's a critical error

            # Use anyio.sleep for async non-blocking sleep
            if interval < self.min_poll_interval:
                logger.warning(
                    f"IdP requested unsafe polling interval {interval}s. Enforcing minimum {self.min_poll_interval}s."
                )
            safe_interval = max(interval, self.min_poll_interval)
            await anyio.sleep(safe_interval)

        if time.time() >= safety_end_time:
            raise CoreasonIdentityError("Polling timed out (safety limit reached).")

        raise CoreasonIdentityError("Polling timed out.")
