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
from unittest.mock import patch

import pytest
from pydantic import SecretStr

from coreason_identity.exceptions import CoreasonIdentityError, IdentityMappingError
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


def test_map_claims_pii_sanitization_in_exception(mapper: IdentityMapper) -> None:
    """
    Ensure that validation errors strip PII (the 'input' field) from the exception message.
    """
    claims = {
        "sub": "user123",
        "email": "invalid-email-format",  # Invalid email
    }

    # We expect IdentityMappingError, and we want to inspect its string representation
    with pytest.raises(IdentityMappingError) as exc_info:
        mapper.map_claims(claims)

    error_msg = str(exc_info.value)
    # The error should contain the field name 'email' and the error type
    assert "email" in error_msg
    assert "value is not a valid email address" in error_msg
    # The error should NOT contain the raw invalid value 'invalid-email-format'
    assert "invalid-email-format" not in error_msg
    # Check that 'input' key is not present in the stringified dict structure if any
    assert "'input':" not in error_msg


def test_map_claims_nested_validation_error_pii(mapper: IdentityMapper) -> None:
    """Test PII sanitization for nested errors (e.g. invalid group enum)."""
    claims = {
        "sub": "user123",
        "email": "test@example.com",
        "groups": ["invalid_group_name"],  # Invalid enum value
    }

    with pytest.raises(IdentityMappingError) as exc_info:
        mapper.map_claims(claims)

    error_msg = str(exc_info.value)
    assert "groups" in error_msg
    # The raw value 'invalid_group_name' should NOT be in the error message
    assert "invalid_group_name" not in error_msg


def test_map_claims_massive_error_list(mapper: IdentityMapper) -> None:
    """Test that massive validation errors don't cause DoS or expose PII."""
    # Generate 100 invalid groups
    invalid_groups = [f"invalid_{i}" for i in range(100)]
    claims = {
        "sub": "user123",
        "email": "test@example.com",
        "groups": invalid_groups,
    }

    with pytest.raises(IdentityMappingError) as exc_info:
        mapper.map_claims(claims)

    error_msg = str(exc_info.value)
    # Ensure no PII leaked
    for g in invalid_groups:
        assert g not in error_msg
    # Ensure it didn't crash
    assert "groups" in error_msg


def test_map_claims_re_raises_coreason_identity_error(mapper: IdentityMapper) -> None:
    """Test that CoreasonIdentityError is re-raised as-is."""
    # We mock RawIdPClaims to raise CoreasonIdentityError
    with patch("coreason_identity.identity_mapper.RawIdPClaims") as mock_cls:
        mock_cls.side_effect = CoreasonIdentityError("Existing error")

        with pytest.raises(CoreasonIdentityError, match="Existing error"):
            mapper.map_claims({"sub": "u1", "email": "e@m.com"})
