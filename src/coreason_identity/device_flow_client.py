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
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import anyio
import httpx
from anyio.from_thread import start_blocking_portal
from pydantic import ValidationError

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import DeviceFlowResponse, TokenResponse
from coreason_identity.utils.logger import logger


class DeviceFlowClientAsync:
    """
    Handles the OAuth 2.0 Device Authorization Grant flow (RFC 8628) - Async.
    """

    def __init__(
        self,
        client_id: str,
        idp_url: str,
        scope: str = "openid profile email",
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        """
        Initialize the DeviceFlowClientAsync.

        Args:
            client_id: The OIDC Client ID.
            idp_url: The base URL of the Identity Provider.
            scope: The scopes to request.
            client: Optional external httpx.AsyncClient.
        """
        self.client_id = client_id
        self.idp_url = idp_url.rstrip("/")
        self.scope = scope
        self._endpoints: Optional[Dict[str, str]] = None

        self._internal_client = client is None
        self._client = client

    async def __aenter__(self) -> "DeviceFlowClientAsync":
        if self._client is None:
            self._client = httpx.AsyncClient()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._internal_client and self._client:
            await self._client.aclose()

    async def _get_endpoints(self) -> Dict[str, str]:
        """
        Discover OIDC endpoints from the IdP.
        """
        if self._endpoints:
            return self._endpoints

        if not self._client:
             raise CoreasonIdentityError("Client not initialized. Use 'async with' context manager.")

        discovery_url = f"{self.idp_url}/.well-known/openid-configuration"

        try:
            response = await self._client.get(discovery_url)
            response.raise_for_status()
            try:
                config = response.json()
            except ValueError as e:
                raise CoreasonIdentityError(f"Invalid JSON response from OIDC discovery: {e}") from e

            device_endpoint = config.get(
                "device_authorization_endpoint", urljoin(f"{self.idp_url}/", "oauth/device/code")
            )
            token_endpoint = config.get("token_endpoint", urljoin(f"{self.idp_url}/", "oauth/token"))

            self._endpoints = {
                "device_authorization_endpoint": device_endpoint,
                "token_endpoint": token_endpoint,
            }
            return self._endpoints
        except httpx.HTTPError as e:
            raise CoreasonIdentityError(f"Failed to discover OIDC endpoints: {e}") from e

    async def initiate_flow(self, audience: Optional[str] = None) -> DeviceFlowResponse:
        """
        Initiates the Device Authorization Flow.
        """
        endpoints = await self._get_endpoints()
        url = endpoints["device_authorization_endpoint"]

        if not self._client:
             raise CoreasonIdentityError("Client not initialized. Use 'async with' context manager.")

        data = {
            "client_id": self.client_id,
            "scope": self.scope,
        }
        if audience:
            data["audience"] = audience

        try:
            response = await self._client.post(url, data=data)
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
        """
        endpoints = await self._get_endpoints()
        url = endpoints["token_endpoint"]

        if not self._client:
             raise CoreasonIdentityError("Client not initialized. Use 'async with' context manager.")

        device_code = device_response.device_code
        interval = device_response.interval
        expires_in = device_response.expires_in

        start_time = time.time()
        end_time = start_time + expires_in

        logger.info(f"Polling for token. Expires in {expires_in}s. Interval: {interval}s")

        while time.time() < end_time:
            data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": self.client_id,
            }

            try:
                response = await self._client.post(url, data=data)

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
                    response.raise_for_status()
                    raise CoreasonIdentityError(f"Received invalid response: {response.text}") from e

                if not isinstance(error_resp, dict):
                    raise CoreasonIdentityError(f"Received invalid JSON response: {error_resp}")

                error = error_resp.get("error")

                if error == "authorization_pending":
                    pass  # Continue polling
                elif error == "slow_down":
                    interval += 5
                    logger.debug("Received slow_down, increasing interval.")
                elif error == "expired_token":
                    raise CoreasonIdentityError("Device code expired.")
                elif error == "access_denied":
                    raise CoreasonIdentityError("User denied access.")
                else:
                    response.raise_for_status()

            except httpx.HTTPStatusError as e:
                logger.error(f"Polling failed with status {e.response.status_code}: {e}")
                raise CoreasonIdentityError(f"Polling failed: {e}") from e

            except Exception as e:
                if isinstance(e, CoreasonIdentityError):
                    raise
                logger.warning(f"Polling attempt failed: {e}")

            await anyio.sleep(interval)

        raise CoreasonIdentityError("Polling timed out.")


class DeviceFlowClient:
    """
    Sync Facade for DeviceFlowClientAsync.
    """

    def __init__(self, client_id: str, idp_url: str, scope: str = "openid profile email") -> None:
        self._async = DeviceFlowClientAsync(client_id, idp_url, scope)
        self._portal_cm: Any = None
        self._portal: Any = None

    def __enter__(self) -> "DeviceFlowClient":
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

    def initiate_flow(self, audience: Optional[str] = None) -> DeviceFlowResponse:
        if not self._portal:
             raise CoreasonIdentityError("Context not started. Use 'with DeviceFlowClient(...):'.")
        return self._portal.call(self._async.initiate_flow, audience)

    def poll_token(self, device_response: DeviceFlowResponse) -> TokenResponse:
        if not self._portal:
             raise CoreasonIdentityError("Context not started. Use 'with DeviceFlowClient(...):'.")
        return self._portal.call(self._async.poll_token, device_response)
