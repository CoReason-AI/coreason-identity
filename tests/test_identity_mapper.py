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
Tests for IdentityMapper.
"""

from typing import Any

import pytest
from pydantic import SecretStr

from coreason_identity.exceptions import IdentityMappingError
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.models import CoreasonGroup, CoreasonScope


@pytest.fixture
def mapper() -> IdentityMapper:
    return IdentityMapper()


def test_map_claims_basic(mapper: IdentityMapper) -> None:
    claims: dict[str, Any] = {"sub": "user123", "email": "test@example.com"}
    ctx = mapper.map_claims(claims, token="tok")

    assert ctx.user_id == "user123"
    assert ctx.email == "test@example.com"
    assert ctx.downstream_token == SecretStr("tok")
    assert ctx.groups == []
    assert ctx.scopes == []


def test_map_claims_group_sources(mapper: IdentityMapper) -> None:
    """Test that groups are resolved from standard 'groups' claim."""
    # 1. Standard 'groups'
    claims1: dict[str, Any] = {"sub": "u1", "email": "u1@e.com", "groups": ["admin"]}
    ctx = mapper.map_claims(claims1)

    # Assert that strings are converted to Enums
    assert ctx.groups == [CoreasonGroup.ADMIN]


def test_map_claims_scopes(mapper: IdentityMapper) -> None:
    """Test scope parsing from 'scope' string."""
    # 1. 'scope' string
    claims1: dict[str, Any] = {"sub": "u1", "email": "u@e.com", "scope": "openid profile"}
    # Assert that strings are converted to Enums
    assert mapper.map_claims(claims1).scopes == [CoreasonScope.OPENID, CoreasonScope.PROFILE]

    # 2. Empty scope
    claims2: dict[str, Any] = {"sub": "u2", "email": "u@e.com", "scope": ""}
    assert mapper.map_claims(claims2).scopes == []

    # 3. No scope
    claims3: dict[str, Any] = {"sub": "u3", "email": "u@e.com"}
    assert mapper.map_claims(claims3).scopes == []


def test_map_claims_missing_required(mapper: IdentityMapper) -> None:
    with pytest.raises(IdentityMappingError):
        mapper.map_claims({"sub": "no-email"})
