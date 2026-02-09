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

import re
from typing import Any

from pydantic import BaseModel, EmailStr, Field, SecretStr, ValidationError, field_validator

from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.models import UserContext
from coreason_identity.utils.logger import logger


class RawIdPClaims(BaseModel):
    """
    Internal model to parse and normalize incoming IdP claims.
    Validates structure and normalizes types (e.g., ensuring lists) before business logic.

    Attributes:
        sub (str): The subject (user ID) from the IdP.
        email (EmailStr): The user's email address.
        project_id_claim (str | None): Custom claim for project ID.
        groups (list[str]): List of groups the user belongs to.
        permissions (list[str]): List of permissions granted to the user.
        scope (str | None): The raw scope string (standard OAuth2 claim).
    """

    sub: str
    email: EmailStr

    # Optional raw fields
    project_id_claim: str | None = Field(default=None, alias="https://coreason.com/project_id")

    # Normalized lists from standard keys
    groups: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)

    # Standard OAuth2 claim is 'scope' (string space-delimited)
    scope: str | None = None

    @field_validator("groups", "permissions", mode="before")
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
            try:
                raw_claims = RawIdPClaims(**claims)
            except ValidationError as e:
                # Map missing required fields (sub, email) to InvalidTokenError
                # because it means the token payload is insufficient for the app.
                raise InvalidTokenError(f"UserContext validation failed: {e}") from e

            # 2. Extract Basic Identity
            sub = raw_claims.sub
            email = raw_claims.email
            groups = raw_claims.groups
            permissions = raw_claims.permissions

            # Parse scopes from standard 'scope' claim
            scopes = raw_claims.scope.split() if raw_claims.scope else []

            # 3. Resolve Project Context
            # Priority: https://coreason.com/project_id -> group pattern "project:<id>"
            project_context = raw_claims.project_id_claim

            if not project_context:
                for group in groups:
                    # Use regex for robust case-insensitive matching and extraction
                    match = re.match(r"^project:\s*(.*)", group, re.IGNORECASE)
                    if match:
                        possible_id = match.group(1).strip()
                        if possible_id:
                            project_context = possible_id
                            break

            # 4. Resolve Permissions
            # Priority: explicit 'permissions' claim (already parsed)
            # No fallback logic to "admin" group for security reasons (avoid implicit privilege escalation)

            # 5. Construct Extended Claims
            # We preserve all original claims and add derived ones for convenience if not present
            extended_claims = claims.copy()
            if project_context is not None:
                extended_claims["project_context"] = project_context

            # Always ensure permissions is a list
            extended_claims["permissions"] = permissions

            # 6. Construct UserContext
            user_context = UserContext(
                user_id=sub,
                email=email,
                groups=groups,
                scopes=scopes,
                downstream_token=SecretStr(token) if token else None,
                claims=extended_claims,
            )

            logger.debug(f"Mapped identity for user {sub}")
            return user_context

        except Exception as e:
            # Catch unexpected exceptions (InvalidTokenError raised above bypasses this)
            if isinstance(e, CoreasonIdentityError):
                raise
            logger.exception("Unexpected error during identity mapping")
            raise CoreasonIdentityError(f"Identity mapping error: {e}") from e
