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

from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.models import UserContext
from coreason_identity.utils.logger import logger


class IdentityMapper:
    """
    Maps validated IdP claims to the standardized internal UserContext.
    """

    def _ensure_list(self, value: Any) -> List[str]:
        """Helper to ensure value is a list of strings."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return []

    def map_claims(self, claims: Dict[str, Any]) -> UserContext:
        """
        Transform raw IdP claims into a UserContext object.

        Args:
            claims: The dictionary of validated claims from the JWT.

        Returns:
            A populated UserContext object.

        Raises:
            CoreasonIdentityError: If required claims are missing or validation fails.
        """
        try:
            # 1. Extract Basic Identity
            sub = claims.get("sub")
            email = claims.get("email")

            if not sub:
                raise CoreasonIdentityError("Missing required claim: 'sub'")
            if not email:
                raise CoreasonIdentityError("Missing required claim: 'email'")

            # 2. Resolve Groups (Standardize diverse claim names)
            # We look for https://coreason.com/groups, groups, or roles
            raw_groups = claims.get("https://coreason.com/groups") or claims.get("groups") or claims.get("roles") or []
            groups = self._ensure_list(raw_groups)

            # 3. Resolve Project Context
            # Priority: https://coreason.com/project_id -> group pattern "project:<id>"
            project_context: Optional[str] = claims.get("https://coreason.com/project_id")

            if not project_context:
                for group in groups:
                    if group.lower().startswith("project:"):
                        # Extract everything after "project:"
                        possible_id = group[8:].strip()
                        if possible_id:
                            project_context = possible_id
                            # Spec doesn't say what to do if multiple exist, assuming first match is sufficient
                            break

            # 4. Resolve Permissions
            # Priority: explicit 'permissions' claim -> group mapping
            raw_permissions = claims.get("permissions")
            permissions: List[str] = self._ensure_list(raw_permissions) if raw_permissions else []

            if not permissions:
                # Fallback: Map groups to permissions
                # Rule: if group is "admin" (case-insensitive), assign ["*"]
                if any(g.lower() == "admin" for g in groups):
                    permissions = ["*"]

            # 5. Construct UserContext
            # Pydantic will handle further validation (e.g. email format)
            user_context = UserContext(
                sub=sub,
                email=email,
                project_context=project_context,
                permissions=permissions,
            )

            logger.debug(f"Mapped identity for user {sub} to project {project_context}")
            return user_context

        except ValidationError as e:
            logger.error(f"Identity mapping failed due to validation error: {e}")
            raise CoreasonIdentityError(f"UserContext validation failed: {e}") from e
        except Exception as e:
            if isinstance(e, CoreasonIdentityError):
                raise
            logger.exception("Unexpected error during identity mapping")
            raise CoreasonIdentityError(f"Identity mapping error: {e}") from e
