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
Data models for the coreason-identity package.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr


class UserContext(BaseModel):
    """
    Standardized User Context object to be available throughout the middleware stack.

    This model is frozen (immutable) to ensure integrity as it passes through the system.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="ignore",
        json_schema_extra={
            "example": {
                "user_id": "auth0|123456",
                "email": "alice@coreason.ai",
                "groups": ["admin", "project:apollo"],
                "scopes": ["openid", "profile", "read:reports"],
            }
        },
    )

    user_id: str = Field(
        ...,
        description="The immutable subject ID (e.g., 'sub'). Unique identifier for the user.",
        examples=["auth0|123456"],
    )
    email: EmailStr = Field(
        ..., description="The user's email address. Verified and strictly typed.", examples=["alice@coreason.ai"]
    )
    groups: list[str] = Field(
        default_factory=list,
        description="Security group IDs. Used for Row-Level Security (RLS).",
        examples=[["admin", "project:apollo"]],
    )
    scopes: list[str] = Field(
        default_factory=list,
        description="OAuth 2.0 scopes for coarse-grained API permission checks.",
        examples=[["openid", "profile"]],
    )
    downstream_token: SecretStr | None = Field(
        default=None, description="The On-Behalf-Of (OBO) token for downstream API calls. Protected from logging."
    )
    claims: dict[str, Any] = Field(default_factory=dict, description="Extended attributes and legacy field mappings.")

    def __repr__(self) -> str:
        return (
            f"UserContext(user_id={self.user_id!r}, "
            f"email={self.email!r}, "
            f"groups={self.groups!r}, "
            f"scopes={self.scopes!r}, "
            f"downstream_token={self.downstream_token!r}, "
            f"claims='<REDACTED>')"
        )

    def __str__(self) -> str:
        return self.__repr__()


class DeviceFlowResponse(BaseModel):
    """
    Response from the Device Authorization Request.

    Attributes:
        device_code (str): The device verification code.
        user_code (str): The code the user should enter at the verification URI.
        verification_uri (str): The URI the user should visit to authorize the device.
        verification_uri_complete (Optional[str]): The complete URI including the user code.
        expires_in (int): The lifetime in seconds of the device_code and user_code.
        interval (int): The minimum amount of time in seconds that the client SHOULD wait between polling requests.
    """

    model_config = ConfigDict(frozen=True)

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None = None
    expires_in: int
    interval: int = 5


class TokenResponse(BaseModel):
    """
    Response containing the tokens.

    Attributes:
        access_token (str): The access token issued by the authorization server.
        refresh_token (Optional[str]): The refresh token, if issued.
        id_token (Optional[str]): The ID token, if issued.
        token_type (str): The type of the token (e.g. "Bearer").
        expires_in (int): The lifetime in seconds of the access token.
    """

    model_config = ConfigDict(frozen=True)

    access_token: str
    refresh_token: str | None = None
    id_token: str | None = None
    token_type: str
    expires_in: int
