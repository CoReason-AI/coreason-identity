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
from typing import Dict, Optional
from urllib.parse import urljoin

import httpx
from pydantic import ValidationError

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import DeviceFlowResponse, TokenResponse
from coreason_identity.utils.logger import logger


class DeviceFlowClient:
    """
    Handles the OAuth 2.0 Device Authorization Grant flow (RFC 8628).

    Attributes:
        client_id (str): The OIDC Client ID.
        idp_url (str): The base URL of the Identity Provider.
        scope (str): The scopes to request.
    """

    def __init__(self, client_id: str, idp_url: str, scope: str = "openid profile email") -> None:
        """
        Initialize the DeviceFlowClient.

        Args:
            client_id: The OIDC Client ID.
            idp_url: The base URL of the Identity Provider (e.g., https://my-tenant.auth0.com).
            scope: The scopes to request (default: "openid profile email").
        """
        self.client_id = client_id
        # Ensure idp_url does not end with a slash for consistent joining,
        # although urljoin handles some cases, strict base is better.
        self.idp_url = idp_url.rstrip("/")
        self.scope = scope
        self._endpoints: Optional[Dict[str, str]] = None

    def _get_endpoints(self) -> Dict[str, str]:
        """
        Discover OIDC endpoints from the IdP.

        Returns:
            A dictionary containing the discovered endpoints.

        Raises:
            CoreasonIdentityError: If OIDC discovery fails.
        """
        if self._endpoints:
            return self._endpoints

        # Use urljoin, but note that urljoin behavior depends on trailing slashes.
        # We ensured self.idp_url has no trailing slash.
        # So we append a slash before joining relative path .well-known/...
        # Actually, simpler to just use f-string with verified structure or just ensure the path starts with /

        discovery_url = f"{self.idp_url}/.well-known/openid-configuration"

        try:
            with httpx.Client() as client:
                response = client.get(discovery_url)
                response.raise_for_status()
                try:
                    config = response.json()
                except ValueError as e:
                    raise CoreasonIdentityError(f"Invalid JSON response from OIDC discovery: {e}") from e

                # Fallback to standard Auth0 paths if not in config
                # urljoin is good for constructing absolute URLs from a base

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

    def initiate_flow(self, audience: Optional[str] = None) -> DeviceFlowResponse:
        """
        Initiates the Device Authorization Flow.

        Args:
            audience: Optional audience for the token.

        Returns:
            DeviceFlowResponse containing device_code, user_code, verification_uri, etc.

        Raises:
            CoreasonIdentityError: If the flow initiation fails or the response is invalid.
        """
        endpoints = self._get_endpoints()
        url = endpoints["device_authorization_endpoint"]

        data = {
            "client_id": self.client_id,
            "scope": self.scope,
        }
        if audience:
            data["audience"] = audience

        try:
            with httpx.Client() as client:
                response = client.post(url, data=data)
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

    def poll_token(self, device_response: DeviceFlowResponse) -> TokenResponse:
        """
        Polls the token endpoint until the user authorizes the device or the code expires.

        Args:
            device_response: The response from initiate_flow.

        Returns:
            TokenResponse containing access_token, refresh_token, etc.

        Raises:
            CoreasonIdentityError: If polling fails, times out, or the request is denied.
        """
        endpoints = self._get_endpoints()
        url = endpoints["token_endpoint"]
        device_code = device_response.device_code
        interval = device_response.interval
        expires_in = device_response.expires_in

        start_time = time.time()
        end_time = start_time + expires_in

        logger.info(f"Polling for token. Expires in {expires_in}s. Interval: {interval}s")

        with httpx.Client() as client:
            while time.time() < end_time:
                data = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": self.client_id,
                }

                try:
                    response = client.post(url, data=data)

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
                        # If raise_for_status didn't raise (unlikely for non-JSON unless 204?), ensure we treat as error
                        raise CoreasonIdentityError(f"Received invalid response: {response.text}") from e

                    if not isinstance(error_resp, dict):
                        # OIDC error response must be a JSON object
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
                    # Decide if we should continue or abort.
                    # If it's a critical error (like strict json check above), we might want to stop?
                    # But for now we just log and continue, assuming transient issue.
                    # Wait, if `response.raise_for_status()` raised HTTPStatusError, it's caught above.
                    # If `ValueError` from json(), we called raise_for_status().

                time.sleep(interval)

        raise CoreasonIdentityError("Polling timed out.")
