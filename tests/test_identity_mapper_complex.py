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

import pytest

from coreason_identity.identity_mapper import IdentityMapper


@pytest.fixture  # type: ignore[misc]
def mapper() -> IdentityMapper:
    return IdentityMapper()


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
    """Test _ensure_list with unsupported type (e.g. dict or int directly)."""
    # Direct int input for groups
    claims1: Dict[str, Any] = {"sub": "u1", "email": "u@e.com", "groups": 123}
    context1 = mapper.map_claims(claims1)
    # _ensure_list(123) -> fallback to []
    assert context1.permissions == []
    assert context1.project_context is None

    # Dict input for permissions (not list or str)
    claims2: Dict[str, Any] = {"sub": "u1", "email": "u@e.com", "permissions": {"read": True}}
    context2 = mapper.map_claims(claims2)
    # _ensure_list({...}) -> fallback to []
    assert context2.permissions == []


def test_ensure_list_direct_coverage(mapper: IdentityMapper) -> None:
    """Directly test _ensure_list to guarantee coverage of all branches."""
    # Test None
    assert mapper._ensure_list(None) == []
    # Test str (Line 32 coverage)
    assert mapper._ensure_list("valid_string") == ["valid_string"]
    # Test list
    assert mapper._ensure_list(["a", "b"]) == ["a", "b"]
    # Test mixed list
    assert mapper._ensure_list(["a", 1]) == ["a", "1"]
    # Test other type
    assert mapper._ensure_list(123) == []
