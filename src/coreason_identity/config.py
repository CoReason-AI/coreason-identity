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

from typing import Optional
from urllib.parse import urlparse

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CoreasonIdentityConfig(BaseSettings):
    """
    Configuration settings for coreason-identity.

    Attributes:
        domain (str): The domain of the Identity Provider (e.g. auth.coreason.com).
        audience (str): The expected audience for the token.
        client_id (Optional[str]): The OIDC Client ID (required for device flow).
    """

    model_config = SettingsConfigDict(
        env_prefix="COREASON_AUTH_",
        case_sensitive=False,
    )

    domain: str
    audience: str
    client_id: Optional[str] = None

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
