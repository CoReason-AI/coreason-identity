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
IdentityMapper component for mapping IdP claims to internal UserContext.
"""

from typing import Any

from pydantic import BaseModel, EmailStr, Field, SecretStr, ValidationError, field_validator

from coreason_identity.exceptions import (
    CoreasonIdentityError,
    IdentityMappingError,
    InvalidTokenError,
)
from coreason_identity.models import UserContext
from coreason_identity.utils.logger import logger


class RawIdPClaims(BaseModel):
    """
    Internal model to parse and normalize incoming IdP claims.
    Validates structure and normalizes types (e.g., ensuring lists) before business logic.

    Attributes:
        sub (str): The subject (user ID) from the IdP.
        email (EmailStr): The user's email address.
        groups (list[str]): List of groups the user belongs to.
        scope (str | None): The raw scope string (standard OAuth2 claim).
    """

    sub: str
    email: EmailStr

    # Normalized lists from standard keys
    groups: list[str] = Field(default_factory=list)

    # Standard OAuth2 claim is 'scope' (string space-delimited)
    scope: str | None = None

    @field_validator("groups", mode="before")
    @classmethod
    def ensure_list_of_strings(cls, v: Any) -> list[str]:
        """Ensures the value is a list of strings, filtering out None values."""
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list | tuple):
            return [str(item) for item in v if item is not None]
        return []


class IdentityMapper:
    """
    Maps validated IdP claims to the standardized internal UserContext.
    """

    def map_claims(self, claims: dict[str, Any], token: str | None = None) -> UserContext:
        """
        Transform raw IdP claims into a UserContext object.

        Args:
            claims: The dictionary of validated claims from the JWT.
            token: The raw access token (optional), to be stored as a downstream token.

        Returns:
            A populated UserContext object.

        Raises:
            InvalidTokenError: If required claims are missing or validation fails.
            CoreasonIdentityError: For unexpected errors.
        """
        try:
            # 1. Parse and Normalize Inputs using Pydantic
            # Note: ValidationError is caught in the outer block to ensure safe logging
            raw_claims = RawIdPClaims(**claims)

            # 2. Extract Basic Identity
            sub = raw_claims.sub
            email = raw_claims.email
            groups = raw_claims.groups

            # Parse scopes from standard 'scope' claim
            scopes = raw_claims.scope.split() if raw_claims.scope else []

            # 3. Construct UserContext
            # Note: Pydantic validation in UserContext will enforce strict Enum values for groups/scopes.
            # Any invalid value will raise ValidationError, caught below.
            # Finding #1: Debug logging removed to prevent PII leak (raw sub).
            return UserContext(
                user_id=sub,
                email=email,
                groups=groups,
                scopes=scopes,
                downstream_token=SecretStr(token) if token else None,
            )

        except Exception as e:
            # Catch unexpected exceptions (InvalidTokenError raised above bypasses this)
            if isinstance(e, CoreasonIdentityError):
                raise
            # Specifically catch ValidationError from RawIdPClaims or UserContext instantiation
            if isinstance(e, ValidationError):
                # Sanitize error: extract 'loc' and 'msg', exclude 'input' and 'ctx' (PII)
                sanitized_errors = []
                for err in e.errors():
                    sanitized_errors.append(
                        {"loc": err.get("loc"), "msg": err.get("msg"), "type": err.get("type")}
                    )

                error_msg = f"UserContext validation failed: {sanitized_errors}"
                # Log sanitized message only
                logger.error(error_msg)
                raise IdentityMappingError(error_msg) from e

            logger.exception("Unexpected error during identity mapping")
            raise CoreasonIdentityError(f"Identity mapping error: {e}") from e
