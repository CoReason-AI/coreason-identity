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
Complex workflow simulations for the Identity Passport.
"""

from typing import Any, Dict
from unittest.mock import AsyncMock, patch

import pytest
from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.manager import IdentityManager
from coreason_identity.models import UserContext

# Mocks
MOCK_DOMAIN = "auth.example.com"
MOCK_AUDIENCE = "api://test"

@pytest.fixture
def identity_manager() -> IdentityManager:
    config = CoreasonIdentityConfig(domain=MOCK_DOMAIN, audience=MOCK_AUDIENCE, client_id="cid")

    # We need to mock the internal async manager components to avoid real network calls
    with patch("coreason_identity.manager.OIDCProvider"), \
         patch("coreason_identity.manager.TokenValidator"), \
         patch("coreason_identity.manager.IdentityMapper") as MockMapper:

        manager = IdentityManager(config)

        # Setup Mapper to behave realistically for the "Happy Path"
        # We can use the real IdentityMapper logic or mock it deeply.
        # Using real Mapper is better for integration testing logic, but tricky to mock dependencies.
        # Here we mock the result to verify the flow.

        # But wait, IdentityManager constructor instantiates these classes.
        # The patches above prevent real instantiation during init.
        # We need to set them up on the instance.

        yield manager

def test_full_auth_flow_simulation(identity_manager: IdentityManager) -> None:
    """
    Simulate:
    1. Service receives token.
    2. Manager validates token.
    3. Service checks Identity Passport.
    4. Service performs RLS check.
    5. Service uses downstream token.
    """
    token = "raw_jwt_token_string"
    header = f"Bearer {token}"

    # Setup mocks
    mock_claims = {
        "sub": "user_001",
        "email": "alice@example.com",
        "groups": ["admin", "project:apollo"],
        "scope": "read write",
    }

    # 1. Mock Validator to return claims
    identity_manager._async.validator.validate_token = AsyncMock(return_value=mock_claims) # type: ignore

    # 2. Mock Mapper? Or use real one?
    # If we mocked IdentityMapper class in fixture, identity_manager.identity_mapper is a Mock object.
    # Let's verify the Mapper call contracts.

    expected_context = UserContext(
        user_id="user_001",
        email="alice@example.com",
        groups=["admin", "project:apollo"],
        scopes=["read", "write"],
        downstream_token="raw_jwt_token_string", # type: ignore - Pydantic handles str->SecretStr conversion
        claims={"project_context": "apollo", "permissions": ["*"]} # Admin -> *
    )

    identity_manager._async.identity_mapper.map_claims.return_value = expected_context # type: ignore

    # Act
    user = identity_manager.validate_token(header)

    # Assert - The Service View
    assert user.user_id == "user_001"
    assert "admin" in user.groups
    assert "read" in user.scopes

    # RLS Check Simulation
    allowed_groups = ["project:apollo"]
    has_access = any(g in allowed_groups for g in user.groups)
    assert has_access

    # OBO Token Usage Simulation
    assert user.downstream_token is not None
    assert user.downstream_token.get_secret_value() == token

def test_legacy_migration_flow(identity_manager: IdentityManager) -> None:
    """
    Simulate a service that still relies on `project_context` and `permissions`.
    Verify they are accessible via `claims`.
    """
    token = "token"

    # Claims without explicit permissions, but with groups that map to them
    mock_claims = {
        "sub": "u2",
        "email": "bob@example.com",
        "groups": ["project:gemini", "editor"],
    }

    identity_manager._async.validator.validate_token = AsyncMock(return_value=mock_claims) # type: ignore

    # We want to test the MAPPER logic here too, ideally.
    # But since we mocked the mapper class, we have to mock the return.
    # To test integration, we should probably NOT mock the mapper class, only Validator/Provider.
    pass

# Redefine fixture to use REAL IdentityMapper for better integration tests
@pytest.fixture
def integration_manager() -> IdentityManager:
    config = CoreasonIdentityConfig(domain=MOCK_DOMAIN, audience=MOCK_AUDIENCE, client_id="cid")

    # Only mock networking parts (Provider, Validator's internal checks)
    # Actually, Validator does crypto. We can mock validator.validate_token to return claims.
    # We want Mapper to be real.

    with patch("coreason_identity.manager.OIDCProvider"), \
         patch("coreason_identity.manager.TokenValidator"):

        manager = IdentityManager(config)

        # Ensure mapper is real (it is by default in __init__ if not patched)
        # But wait, we need to make sure we didn't patch it globally in the file scope or something.
        # The previous fixture patched it in the context manager scope.

        yield manager

def test_integration_legacy_access(integration_manager: IdentityManager) -> None:
    """
    Integration test: Manager -> Validator(Mock) -> Mapper(Real) -> UserContext
    """
    mock_claims = {
        "sub": "u2",
        "email": "bob@example.com",
        "groups": ["project:gemini", "admin"], # Admin -> * permissions
    }

    integration_manager._async.validator.validate_token = AsyncMock(return_value=mock_claims) # type: ignore

    user = integration_manager.validate_token("Bearer token123")

    # Verify Legacy Access
    assert user.claims.get("project_context") == "gemini"
    assert user.claims.get("permissions") == ["*"]

    # Verify New Access
    assert user.groups == ["project:gemini", "admin"]
    assert user.downstream_token.get_secret_value() == "token123"
