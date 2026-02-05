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
Edge case tests specifically for the new Identity Mapper logic and UserContext.
"""

import pytest
from coreason_identity.exceptions import InvalidTokenError
from coreason_identity.identity_mapper import IdentityMapper


@pytest.fixture()
def mapper() -> IdentityMapper:
    return IdentityMapper()


def test_mapper_missing_downstream_token(mapper: IdentityMapper) -> None:
    """Test mapping without providing a token string."""
    claims = {"sub": "u1", "email": "u@e.com"}
    context = mapper.map_claims(claims)  # Token arg is optional
    assert context.downstream_token is None


def test_mapper_scopes_parsing_variations(mapper: IdentityMapper) -> None:
    """Test various formats of scope/scp claims."""
    # 1. 'scope' as space-delimited string
    c1 = {"sub": "u1", "email": "u@e.com", "scope": "read write"}
    assert mapper.map_claims(c1).scopes == ["read", "write"]

    # 2. 'scp' as list
    c2 = {"sub": "u1", "email": "u@e.com", "scp": ["read", "write"]}
    assert mapper.map_claims(c2).scopes == ["read", "write"]

    # 3. 'scopes' as list (explicit field)
    c3 = {"sub": "u1", "email": "u@e.com", "scopes": ["read", "write"]}
    assert mapper.map_claims(c3).scopes == ["read", "write"]

    # 4. 'scope' as single string (no spaces)
    c4 = {"sub": "u1", "email": "u@e.com", "scope": "admin"}
    assert mapper.map_claims(c4).scopes == ["admin"]

    # 5. Missing scope
    c5 = {"sub": "u1", "email": "u@e.com"}
    assert mapper.map_claims(c5).scopes == []

    # 6. Empty string scope
    c6 = {"sub": "u1", "email": "u@e.com", "scope": ""}
    assert mapper.map_claims(c6).scopes == []


def test_mapper_claims_conflicts(mapper: IdentityMapper) -> None:
    """
    Test conflict handling: Explicit 'permissions' in claims vs mapped permissions.
    The logic currently maps legacy fields INTO claims.
    If 'permissions' is in input claims, it is preserved.
    """
    # Case 1: 'permissions' in input claims
    c1 = {"sub": "u1", "email": "u@e.com", "permissions": ["explicit"]}
    ctx1 = mapper.map_claims(c1)
    assert ctx1.claims["permissions"] == ["explicit"]

    # Case 2: 'groups' maps to permissions (admin -> *)
    # BUT 'permissions' is NOT in input.
    c2 = {"sub": "u1", "email": "u@e.com", "groups": ["admin"]}
    ctx2 = mapper.map_claims(c2)
    # Logic: if not permissions (input), map groups.
    # If mapped -> extended_claims["permissions"] = mapped
    assert ctx2.claims["permissions"] == []

    # Case 3: Both exist. Explicit should win (based on code reading).
    # "if not permissions:" check ensures we don't overwrite if permissions exist.
    c3 = {"sub": "u1", "email": "u@e.com", "groups": ["admin"], "permissions": ["explicit"]}
    ctx3 = mapper.map_claims(c3)
    assert ctx3.claims["permissions"] == ["explicit"]


def test_mapper_groups_mixed_types_robustness(mapper: IdentityMapper) -> None:
    """Test groups containing non-string types."""
    # Integers in groups -> parsed as strings by ensure_list_of_strings
    c1 = {"sub": "u1", "email": "u@e.com", "groups": [123, "valid"]}
    ctx1 = mapper.map_claims(c1)
    assert ctx1.groups == ["123", "valid"]

    # None in groups -> filtered out
    c2 = {"sub": "u1", "email": "u@e.com", "groups": [None, "valid"]}
    # ensure_list_of_strings: "if item is not None"
    # But wait, [str(item) for item in v if item is not None]
    ctx2 = mapper.map_claims(c2)
    assert ctx2.groups == ["valid"]


def test_mapper_malformed_email(mapper: IdentityMapper) -> None:
    """Ensure malformed email raises InvalidTokenError."""
    c = {"sub": "u1", "email": "not-an-email"}
    with pytest.raises(InvalidTokenError):
        mapper.map_claims(c)
