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
Tests for IdentityMapper edge cases.
"""

from typing import Any
import pytest
from coreason_identity.identity_mapper import IdentityMapper

@pytest.fixture
def mapper() -> IdentityMapper:
    return IdentityMapper()

def test_mapper_scopes_parsing_variations(mapper: IdentityMapper) -> None:
    """Test standard scope claim parsing."""
    # 1. 'scope' as space-delimited string
    c1: dict[str, Any] = {"sub": "u1", "email": "u@e.com", "scope": "openid profile"}
    assert mapper.map_claims(c1).scopes == ["openid", "profile"]

    # 4. 'scope' as single string (no spaces)
    c4: dict[str, Any] = {"sub": "u1", "email": "u@e.com", "scope": "openid"}
    assert mapper.map_claims(c4).scopes == ["openid"]

    # 5. Missing scope
    c5: dict[str, Any] = {"sub": "u1", "email": "u@e.com"}
    assert mapper.map_claims(c5).scopes == []

    # 6. 'scope' as empty string
    c6: dict[str, Any] = {"sub": "u1", "email": "u@e.com", "scope": ""}
    assert mapper.map_claims(c6).scopes == []
