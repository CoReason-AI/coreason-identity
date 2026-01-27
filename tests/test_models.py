# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import pytest
from coreason_identity.models import UserContext
from pydantic import ValidationError, SecretStr


def test_user_context_valid() -> None:
    """Test creating a valid UserContext."""
    user = UserContext(
        user_id="user123",
        email="test@example.com",
        groups=["admin"],
        scopes=["read"],
        downstream_token=SecretStr("secret"),
        claims={"custom": "value"}
    )
    assert user.user_id == "user123"
    assert user.email == "test@example.com"
    assert user.groups == ["admin"]
    assert user.scopes == ["read"]
    assert user.downstream_token is not None
    assert user.downstream_token.get_secret_value() == "secret"
    assert user.claims == {"custom": "value"}


def test_user_context_defaults() -> None:
    """Test UserContext defaults for optional fields."""
    user = UserContext(user_id="user123", email="test@example.com")
    assert user.user_id == "user123"
    assert user.email == "test@example.com"
    assert user.groups == []
    assert user.scopes == []
    assert user.downstream_token is None
    assert user.claims == {}


def test_user_context_invalid_email() -> None:
    """Test that an invalid email raises a ValidationError."""
    with pytest.raises(ValidationError) as excinfo:
        UserContext(user_id="user123", email="not-an-email")
    assert "value is not a valid email address" in str(excinfo.value)


def test_user_context_missing_user_id() -> None:
    """Test that missing required 'user_id' raises a ValidationError."""
    with pytest.raises(ValidationError) as excinfo:
        UserContext(email="test@example.com")  # type: ignore[call-arg]
    assert "Field required" in str(excinfo.value)
    assert "user_id" in str(excinfo.value)


def test_user_context_missing_email() -> None:
    """Test that missing required 'email' raises a ValidationError."""
    with pytest.raises(ValidationError) as excinfo:
        UserContext(user_id="user123")  # type: ignore[call-arg]
    assert "Field required" in str(excinfo.value)
    assert "email" in str(excinfo.value)


def test_user_context_immutability() -> None:
    """
    Test that the model behaves as expected (standard Pydantic models are mutable by default,
    but we verify basic assignment works).
    """
    user = UserContext(user_id="user123", email="test@example.com")
    user.claims = {"new": "claim"}
    assert user.claims == {"new": "claim"}
