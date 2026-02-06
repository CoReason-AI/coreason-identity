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
Internal data models for the coreason-identity package.
These are not exposed in the public API.
"""

from pydantic import BaseModel, ConfigDict, Field


class OIDCConfig(BaseModel):
    """
    OIDC Configuration from .well-known/openid-configuration.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    issuer: str = Field(..., description="The OIDC issuer URL.")
    jwks_uri: str = Field(..., description="The URL to the JWKS.")
    token_endpoint: str | None = Field(default=None, description="The token endpoint URL.")
    device_authorization_endpoint: str | None = Field(
        default=None, description="The device authorization endpoint URL."
    )
