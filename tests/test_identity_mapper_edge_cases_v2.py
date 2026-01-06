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


class TestIdentityMapperEdgeCasesV2:
    @pytest.fixture
    def mapper(self) -> IdentityMapper:
        return IdentityMapper()

    def test_explicit_empty_permissions_claim(self, mapper: IdentityMapper) -> None:
        """
        Test behavior when 'permissions' claim is explicitly provided as an empty list.
        Does it trigger the admin fallback?
        Current implementation: `if not permissions:` is True for empty list.
        So valid empty list + admin group -> ["*"].
        """
        claims: Dict[str, Any] = {"sub": "u1", "email": "u@e.com", "permissions": [], "groups": ["admin"]}

        context = mapper.map_claims(claims)
        # Expectation: fallback logic runs because permissions is falsy.
        assert context.permissions == ["*"]

    def test_explicit_non_empty_permissions_overrides_admin(self, mapper: IdentityMapper) -> None:
        """
        Test that if permissions are present, admin group is ignored.
        """
        claims: Dict[str, Any] = {"sub": "u1", "email": "u@e.com", "permissions": ["read"], "groups": ["admin"]}

        context = mapper.map_claims(claims)
        assert context.permissions == ["read"]

    def test_large_number_of_groups(self, mapper: IdentityMapper) -> None:
        """
        Test performance/stability with a large list of groups.
        """
        # Create 10,000 groups
        groups = [f"group-{i}" for i in range(10000)]
        # Add a project group at the end
        groups.append("project:FoundMe")

        claims: Dict[str, Any] = {"sub": "u1", "email": "u@e.com", "groups": groups}

        # Should execute reasonably fast
        context = mapper.map_claims(claims)
        assert context.project_context == "FoundMe"
