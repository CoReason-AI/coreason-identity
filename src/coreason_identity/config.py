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

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CoreasonVerifierConfig(BaseSettings):
    """
    Configuration settings for coreason-identity token verification.

    Attributes:
        domain (str): The domain of the Identity Provider (e.g. auth.coreason.com).
        audience (str): The expected audience for the token.
        pii_salt (SecretStr): WARNING: High-entropy salt required for irreversible PII anonymization.
        http_timeout (float): Security boundary: Enforces timeout (in seconds) to prevent DoS via slow responses.
        allowed_algorithms (list[str]): Security boundary: Restricts accepted signing algorithms
            to prevent algorithm confusion attacks.
        clock_skew_leeway (int): Acceptable clock skew in seconds. Defaults to 0 for strict security.
        issuer (str | None): The expected issuer URL. Defaults to https://{domain}/.
    """

    model_config = SettingsConfigDict(
        env_prefix="COREASON_AUTH_",
        case_sensitive=False,
    )

    domain: str = Field(..., description="The domain of the Identity Provider (e.g. auth.coreason.com).")
    audience: str
    pii_salt: SecretStr = Field(..., description="High-entropy salt for PII hashing. REQUIRED.")
    http_timeout: float = Field(..., description="Timeout in seconds for all IdP network operations.")
    allowed_algorithms: list[str] = Field(
        ..., description="List of allowed JWT signing algorithms (e.g., ['RS256']). REQUIRED."
    )
    clock_skew_leeway: int = Field(
        0, description="Acceptable clock skew in seconds. Defaults to 0 for strict security."
    )
    issuer: str | None = None

    @field_validator("domain")
    @classmethod
    def validate_domain_format(cls, v: str) -> str:
        """
        Ensures domain is a hostname, not a URL.
        """
        if "://" in v or "/" in v:
            raise ValueError("Domain must be a hostname (e.g. auth.coreason.com), not a URL.")
        return v

    @model_validator(mode="after")
    def set_default_issuer(self) -> "CoreasonVerifierConfig":
        """
        Sets default issuer if not provided.
        """
        if self.issuer is None:
            self.issuer = f"https://{self.domain}/"
        return self


class CoreasonClientConfig(CoreasonVerifierConfig):
    """
    Configuration settings for coreason-identity OIDC client operations.
    Inherits from CoreasonVerifierConfig and adds client_id.

    Attributes:
        client_id (str): The OIDC Client ID. Required for device flow.
    """

    client_id: str = Field(..., description="OIDC Client ID. Required for device flow.")
