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
from coreason_identity.identity_mapper import IdentityMapper, RawIdPClaims
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


# --- Complex / Edge Case Tests ---


def test_complex_groups_empty_vs_valid(mapper: IdentityMapper) -> None:
    """Test priority when one source is empty list and another is valid."""
    # 'groups' is empty list, 'roles' has data. Should check roles.
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": [],
        "roles": ["project:XYZ"],
    }
    context = mapper.map_claims(claims)
    assert context.project_context == "XYZ"


def test_complex_malformed_project_group(mapper: IdentityMapper) -> None:
    """Test groups that look like 'project:' but have empty ID."""
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": ["project:", "project:  ", "project:VALID"],
    }
    context = mapper.map_claims(claims)
    # Should skip the first two and pick VALID
    assert context.project_context == "VALID"


def test_complex_groups_as_string(mapper: IdentityMapper) -> None:
    """Test if 'groups' is provided as a single string instead of list."""
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": "project:SINGLE",
    }
    context = mapper.map_claims(claims)
    assert context.project_context == "SINGLE"


def test_complex_permissions_as_string(mapper: IdentityMapper) -> None:
    """Test if 'permissions' is provided as a single string."""
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "permissions": "read:all",
    }
    context = mapper.map_claims(claims)
    assert context.permissions == ["read:all"]


def test_complex_case_sensitivity(mapper: IdentityMapper) -> None:
    """Test case insensitivity for 'admin' and 'project:' prefix."""
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": ["ADMIN", "PROJECT:MixedCase"],
    }
    context = mapper.map_claims(claims)
    assert context.permissions == ["*"]
    assert context.project_context == "MixedCase"


def test_complex_whitespace_trimming(mapper: IdentityMapper) -> None:
    """Test that project ID is trimmed of whitespace."""
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": ["project:  spaced_out  "],
    }
    context = mapper.map_claims(claims)
    assert context.project_context == "spaced_out"


def test_complex_mixed_types_in_list(mapper: IdentityMapper) -> None:
    """Test if list contains non-strings (e.g. integers)."""
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": [123, "project:456"],
    }
    # 123 should be converted to "123", not match "project:"
    # "project:456" should match
    context = mapper.map_claims(claims)
    assert context.project_context == "456"


def test_complex_invalid_type_input(mapper: IdentityMapper) -> None:
    """Test _ensure_list logic via Pydantic validator with unsupported type."""
    # Direct int input for groups -> Validator handles it (fallback to [])?
    # Actually, verify our ensure_list_of_strings behavior:
    # if isinstance(v, (list, tuple)) -> str conversion.
    # if str -> [v].
    # else -> [].

    claims1: Dict[str, Any] = {"sub": "u1", "email": "u@e.com", "groups": 123}
    context1 = mapper.map_claims(claims1)
    # 123 is not list, tuple, or str -> []
    assert context1.permissions == []
    assert context1.project_context is None

    # Dict input for permissions (not list or str)
    claims2: Dict[str, Any] = {"sub": "u1", "email": "u@e.com", "permissions": {"read": True}}
    context2 = mapper.map_claims(claims2)
    # _ensure_list({...}) -> fallback to []
    assert context2.permissions == []


def test_ensure_list_of_strings_direct() -> None:
    """Directly test RawIdPClaims.ensure_list_of_strings to guarantee coverage."""
    # Test None
    assert RawIdPClaims.ensure_list_of_strings(None) == []
    # Test str
    assert RawIdPClaims.ensure_list_of_strings("valid_string") == ["valid_string"]
    # Test list
    assert RawIdPClaims.ensure_list_of_strings(["a", "b"]) == ["a", "b"]
    # Test mixed list
    assert RawIdPClaims.ensure_list_of_strings(["a", 1]) == ["a", "1"]
    # Test tuple
    assert RawIdPClaims.ensure_list_of_strings(("a", "b")) == ["a", "b"]
    # Test other type (e.g. int)
    assert RawIdPClaims.ensure_list_of_strings(123) == []


def test_mapper_multiple_project_groups_precedence(mapper: IdentityMapper) -> None:
    """
    Test precedence when multiple groups match the 'project:' pattern.
    The current implementation breaks after the first match.
    """
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": ["project:PRIMARY", "project:SECONDARY"],
    }
    context = mapper.map_claims(claims)
    # Should pick the first one encountered in the list
    assert context.project_context == "PRIMARY"


def test_mapper_list_with_none(mapper: IdentityMapper) -> None:
    """
    Test behavior when 'groups' list contains None.
    The validator converts [str(item) for item in v], so None becomes "None".
    """
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": [None, "admin"],
    }
    context = mapper.map_claims(claims)
    # "None" is just a string, likely won't match "project:", but shouldn't crash.
    # "admin" should map to permissions ["*"]
    assert context.permissions == ["*"]


def test_mapper_empty_project_string(mapper: IdentityMapper) -> None:
    """Test 'project:' with empty ID string."""
    claims: Dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": ["project:", "project:VALID"],
    }
    context = mapper.map_claims(claims)
    # The logic checks `if possible_id:`, so empty string is skipped.
    assert context.project_context == "VALID"
