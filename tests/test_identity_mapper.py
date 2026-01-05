# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from typing import Any, Dict
from unittest.mock import patch

import pytest

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.models import UserContext


@pytest.fixture
def mapper() -> IdentityMapper:
    return IdentityMapper()


def test_map_claims_happy_path_explicit(mapper: IdentityMapper) -> None:
    """Test mapping with all explicit claims provided."""
    claims: Dict[str, Any] = {
        "sub": "user|123",
        "email": "user@example.com",
        "https://coreason.com/project_id": "proj_123",
        "permissions": ["read", "write"],
    }
    context = mapper.map_claims(claims)

    assert isinstance(context, UserContext)
    assert context.sub == "user|123"
    assert context.email == "user@example.com"
    assert context.project_context == "proj_123"
    assert context.permissions == ["read", "write"]


def test_map_claims_project_fallback_to_groups(mapper: IdentityMapper) -> None:
    """Test extracting project context from groups."""
    claims: Dict[str, Any] = {
        "sub": "user|456",
        "email": "dev@example.com",
        "groups": ["developers", "project:proj_ABC", "other"],
    }
    context = mapper.map_claims(claims)

    assert context.project_context == "proj_ABC"
    assert context.permissions == []  # No permissions claims or admin group


def test_map_claims_permissions_fallback_admin(mapper: IdentityMapper) -> None:
    """Test extracting permissions from 'admin' group."""
    claims: Dict[str, Any] = {
        "sub": "admin|789",
        "email": "admin@coreason.com",
        "https://coreason.com/groups": ["admin", "staff"],
    }
    context = mapper.map_claims(claims)

    assert context.permissions == ["*"]
    assert context.project_context is None


def test_map_claims_group_sources(mapper: IdentityMapper) -> None:
    """Test that groups are resolved from various sources (custom, standard, roles)."""
    # 1. Standard 'groups'
    claims1: Dict[str, Any] = {"sub": "u1", "email": "u1@e.com", "groups": ["project:A"]}
    assert mapper.map_claims(claims1).project_context == "A"

    # 2. Custom 'https://coreason.com/groups'
    claims2: Dict[str, Any] = {"sub": "u2", "email": "u2@e.com", "https://coreason.com/groups": ["project:B"]}
    assert mapper.map_claims(claims2).project_context == "B"

    # 3. 'roles'
    claims3: Dict[str, Any] = {"sub": "u3", "email": "u3@e.com", "roles": ["project:C"]}
    assert mapper.map_claims(claims3).project_context == "C"


def test_map_claims_missing_required_fields(mapper: IdentityMapper) -> None:
    """Test that missing sub or email raises CoreasonIdentityError."""
    # Missing sub (Pydantic validation error)
    with pytest.raises(CoreasonIdentityError, match="UserContext validation failed"):
        mapper.map_claims({"email": "valid@email.com"})

    # Missing email (Pydantic validation error)
    with pytest.raises(CoreasonIdentityError, match="UserContext validation failed"):
        mapper.map_claims({"sub": "123"})


def test_map_claims_invalid_email_format(mapper: IdentityMapper) -> None:
    """Test that invalid email format raises CoreasonIdentityError (via Pydantic)."""
    claims: Dict[str, Any] = {
        "sub": "123",
        "email": "not-an-email",
    }
    with pytest.raises(CoreasonIdentityError, match="UserContext validation failed"):
        mapper.map_claims(claims)


def test_map_claims_multiple_project_groups(mapper: IdentityMapper) -> None:
    """Test behavior when multiple project groups exist (should take first)."""
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u1@e.com",
        "groups": ["project:FIRST", "project:SECOND"],
    }
    context = mapper.map_claims(claims)
    assert context.project_context == "FIRST"


def test_map_claims_generic_exception(mapper: IdentityMapper) -> None:
    """Test that a generic exception is caught and wrapped."""
    claims: Dict[str, Any] = {
        "sub": "user|123",
        "email": "user@example.com",
    }

    # Mock RawIdPClaims or UserContext logic if strict isolation needed,
    # but checking standard Exception wrapping here.
    # We patch UserContext constructor because that's called last.
    with patch("coreason_identity.identity_mapper.UserContext") as mock_user_context:
        mock_user_context.side_effect = Exception("Unexpected failure")

        with pytest.raises(CoreasonIdentityError, match="Identity mapping error: Unexpected failure"):
            mapper.map_claims(claims)
