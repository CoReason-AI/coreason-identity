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

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, SecretStr


class UserContext(BaseModel):
    """
    Standardized User Context object to be available throughout the middleware stack.

    Attributes:
        user_id (str): The immutable subject ID (e.g., "sub").
        email (EmailStr): User's email address (for audit logging).
        groups (List[str]): Security group IDs for ACL checks in Catalog.
        scopes (List[str]): OAuth scopes for permission checks.
        downstream_token (Optional[SecretStr]): The On-Behalf-Of token for Microsoft Graph/Connectors.
        claims (Dict[str, Any]): Extended attributes.
    """

    user_id: str
    email: EmailStr
    groups: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    downstream_token: Optional[SecretStr] = None
    claims: Dict[str, Any] = Field(default_factory=dict)


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

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: Optional[str] = None
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

    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    token_type: str
    expires_in: int
