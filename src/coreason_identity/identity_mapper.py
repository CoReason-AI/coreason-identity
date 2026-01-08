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
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator

from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.models import UserContext
from coreason_identity.utils.logger import logger


class RawIdPClaims(BaseModel):
    """
    Internal model to parse and normalize incoming IdP claims.
    Validates structure and normalizes types (e.g., ensuring lists) before business logic.
    """

    sub: str
    email: EmailStr

    # Optional raw fields
    project_id_claim: Optional[str] = Field(default=None, alias="https://coreason.com/project_id")

    # Normalized lists from potentially diverse keys
    # We will use a root validator or specific field validators to populate these
    groups: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)

    @field_validator("groups", "permissions", mode="before")
    @classmethod
    def ensure_list_of_strings(cls, v: Any) -> List[str]:
        """Ensures the value is a list of strings, filtering out None values."""
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, (list, tuple)):
            return [str(item) for item in v if item is not None]
        return []

    def __init__(self, **data: Any) -> None:
        # Pre-process groups from multiple possible sources
        # Logic: If 'groups' is missing OR empty, try other sources.

        # Check if 'groups' is present and truthy in data
        groups_val = data.get("groups")

        if not groups_val:
            # If groups is missing or empty, try the others in order
            raw_groups = data.get("https://coreason.com/groups") or data.get("groups") or data.get("roles") or []
            # Assign back to 'groups' so Pydantic picks it up
            data["groups"] = raw_groups

        super().__init__(**data)


class IdentityMapper:
    """
    Maps validated IdP claims to the standardized internal UserContext.
    """

    def map_claims(self, claims: Dict[str, Any]) -> UserContext:
        """
        Transform raw IdP claims into a UserContext object.

        Args:
            claims: The dictionary of validated claims from the JWT.

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
            # Priority: explicit 'permissions' claim (already parsed) -> group mapping
            if not permissions:
                # Fallback: Map groups to permissions
                # Rule: if group is "admin" (case-insensitive), assign ["*"]
                if any(g.lower() == "admin" for g in groups):
                    permissions = ["*"]

            # 5. Construct UserContext
            user_context = UserContext(
                sub=sub,
                email=email,
                project_context=project_context,
                permissions=permissions,
            )

            logger.debug(f"Mapped identity for user {sub} to project {project_context}")
            return user_context

        except Exception as e:
            # Catch unexpected exceptions (InvalidTokenError raised above bypasses this)
            if isinstance(e, CoreasonIdentityError):
                raise
            logger.exception("Unexpected error during identity mapping")
            raise CoreasonIdentityError(f"Identity mapping error: {e}") from e
