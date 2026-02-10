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

from pydantic import Field, HttpUrl, SecretStr, TypeAdapter, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CoreasonCommonConfig(BaseSettings):
    """
    Common configuration settings for coreason-identity.

    Attributes:
        domain (str): The domain of the Identity Provider (e.g. auth.coreason.com).
        audience (str): The expected audience for the token.
        http_timeout (float): Security boundary: Enforces timeout (in seconds) to prevent DoS via slow responses.
        issuer (str | None): The expected issuer URL. Defaults to https://{domain}/.
    """

    model_config = SettingsConfigDict(
        env_prefix="COREASON_AUTH_",
        case_sensitive=False,
    )

    domain: str = Field(..., description="The domain of the Identity Provider (e.g. auth.coreason.com).")
    audience: str
    http_timeout: float = Field(..., description="Timeout in seconds for all IdP network operations.")
    issuer: str | None = None

    @field_validator("domain")
    @classmethod
    def validate_domain_format(cls, v: str) -> str:
        """
        Ensures domain is a hostname, not a URL.
        """
        # Improved validation: Check against common URL characters that shouldn't be in a hostname
        if "://" in v or "/" in v or "?" in v or "#" in v:
            raise ValueError("Domain must be a hostname (e.g. auth.coreason.com), not a URL.")

        # Use Pydantic's native HttpUrl validation to ensure it forms a valid host
        try:
            TypeAdapter(HttpUrl).validate_python(f"https://{v}")
        except Exception as e:
            raise ValueError(f"Invalid domain format: {e}") from e

        return v

    @model_validator(mode="after")
    def set_default_issuer(self) -> "CoreasonCommonConfig":
        """
        Sets default issuer if not provided.
        """
        if self.issuer is None:
            self.issuer = f"https://{self.domain}/"
        return self


class CoreasonVerifierConfig(CoreasonCommonConfig):
    """
    Configuration settings for coreason-identity token verification.
    Inherits from CoreasonCommonConfig and adds verifier-specific fields.

    Attributes:
        pii_salt (SecretStr): WARNING: High-entropy salt required for irreversible PII anonymization.
        allowed_algorithms (list[str]): Security boundary: Restricts accepted signing algorithms
            to prevent algorithm confusion attacks.
        clock_skew_leeway (int): Acceptable clock skew in seconds. Defaults to 0 for strict security.
    """

    pii_salt: SecretStr = Field(..., description="High-entropy salt for PII hashing. REQUIRED.")
    allowed_algorithms: list[str] = Field(
        ..., description="List of allowed JWT signing algorithms (e.g., ['RS256']). REQUIRED."
    )
    clock_skew_leeway: int = Field(
        0, description="Acceptable clock skew in seconds. Defaults to 0 for strict security."
    )


class CoreasonClientConfig(CoreasonCommonConfig):
    """
    Configuration settings for coreason-identity OIDC client operations.
    Inherits from CoreasonCommonConfig and adds client_id.

    Attributes:
        client_id (str): The OIDC Client ID. Required for device flow.
    """

    client_id: str = Field(..., description="OIDC Client ID. Required for device flow.")
