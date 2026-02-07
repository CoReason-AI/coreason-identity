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

from urllib.parse import urlparse

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CoreasonVerifierConfig(BaseSettings):
    """
    Configuration settings for coreason-identity token verification.

    Attributes:
        domain (str): The domain of the Identity Provider (e.g. auth.coreason.com).
        audience (str): The expected audience for the token.
        pii_salt (SecretStr): Salt for anonymizing PII in logs/traces.
        issuer (str | None): The expected issuer URL. Defaults to https://{domain}/.
    """

    model_config = SettingsConfigDict(
        env_prefix="COREASON_AUTH_",
        case_sensitive=False,
    )

    domain: str
    audience: str
    pii_salt: SecretStr = Field(..., description="High-entropy salt for PII hashing. REQUIRED.")
    http_timeout: float = Field(..., description="Timeout in seconds for all IdP network operations.")
    allowed_algorithms: list[str] = Field(..., description="List of allowed JWT signing algorithms (e.g., ['RS256']). REQUIRED.")
    clock_skew_leeway: int = Field(0, description="Acceptable clock skew in seconds. Defaults to 0 for strict security.")
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
    def set_default_issuer(self) -> "CoreasonVerifierConfig":
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


class CoreasonClientConfig(CoreasonVerifierConfig):
    """
    Configuration settings for coreason-identity OIDC client operations.
    Inherits from CoreasonVerifierConfig and adds client_id.

    Attributes:
        client_id (str): The OIDC Client ID (required for device flow).
    """

    client_id: str = Field(..., description="OIDC Client ID. Required for device flow.")
