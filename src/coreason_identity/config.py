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
Configuration for the coreason-identity package.
"""

import ipaddress
import os
import socket
from urllib.parse import urlparse

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CoreasonIdentityConfig(BaseSettings):
    """
    Configuration settings for coreason-identity.

    Attributes:
        domain (str): The domain of the Identity Provider (e.g. auth.coreason.com).
        audience (str): The expected audience for the token.
        client_id (str | None): The OIDC Client ID (required for device flow).
        pii_salt (SecretStr): Salt for anonymizing PII in logs/traces.
        issuer (str | None): The expected issuer URL. Defaults to https://{domain}/.
    """

    model_config = SettingsConfigDict(
        env_prefix="COREASON_AUTH_",
        case_sensitive=False,
    )

    domain: str
    audience: str
    client_id: str | None = None
    pii_salt: SecretStr = SecretStr("coreason-unsafe-default-salt")
    http_timeout: float = Field(..., description="Timeout in seconds for all IdP network operations.")
    unsafe_local_dev: bool = False
    issuer: str | None = None

    @field_validator("issuer", mode="after")
    @classmethod
    def validate_https(cls, v: str | None, info: ValidationInfo) -> str | None:
        """
        Ensures that issuer uses HTTPS, unless strictly opted out for local dev.
        """
        if v and v.startswith("http://") and not info.data.get("unsafe_local_dev", False):
            raise ValueError("HTTPS is required for production. Set 'unsafe_local_dev=True' only for local testing.")
        return v

    @model_validator(mode="after")
    def set_default_issuer(self) -> "CoreasonIdentityConfig":
        """
        Sets default issuer if not provided.
        """
        if self.issuer is None:
            # self.domain is already normalized by its field validator
            self.issuer = f"https://{self.domain}/"
        return self

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, v: str) -> str:
        """
        Ensures domain is just the hostname (e.g. auth.coreason.com).
        Strips scheme and path if present.

        Args:
            v: The domain string to normalize.

        Returns:
            The normalized hostname string.
        """
        v = v.strip().lower()
        if "://" not in v:
            v = f"https://{v}"

        parsed = urlparse(v)
        return parsed.netloc or v

    @field_validator("domain")
    @classmethod
    def validate_domain_dns(cls, v: str) -> str:
        """
        Validates that the domain does not resolve to a prohibited IP address.
        Prevents SSRF attacks.

        Args:
            v: The normalized domain string.

        Returns:
            The domain string if valid.

        Raises:
            ValueError: If the domain resolves to a private, loopback, or reserved IP.
        """
        # Bypass check if explicitly disabled in dev
        if os.environ.get("COREASON_DEV_UNSAFE_MODE", "").lower() == "true":
            return v

        try:
            # Resolve hostname to IP(s)
            # Use default family/type/proto to get all results
            addr_infos = socket.getaddrinfo(v, None)
        except socket.gaierror as e:
            raise ValueError(f"Unable to resolve domain '{v}': {e}") from e

        for _, _, _, _, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                # Should not happen with valid socket.getaddrinfo results
                continue

            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                raise ValueError(f"Security violation: Domain '{v}' resolves to a prohibited IP ({ip_str})")

        return v
