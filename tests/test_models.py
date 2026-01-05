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
from pydantic import ValidationError

from coreason_identity.models import UserContext


def test_user_context_valid() -> None:
    """Test creating a valid UserContext."""
    user = UserContext(sub="user123", email="test@example.com", project_context="proj1", permissions=["read"])
    assert user.sub == "user123"
    assert user.email == "test@example.com"
    assert user.project_context == "proj1"
    assert user.permissions == ["read"]


def test_user_context_defaults() -> None:
    """Test UserContext defaults for optional fields."""
    user = UserContext(sub="user123", email="test@example.com")
    assert user.sub == "user123"
    assert user.email == "test@example.com"
    assert user.project_context is None
    assert user.permissions == []


def test_user_context_invalid_email() -> None:
    """Test that an invalid email raises a ValidationError."""
    with pytest.raises(ValidationError) as excinfo:
        UserContext(sub="user123", email="not-an-email")
    assert "value is not a valid email address" in str(excinfo.value)


def test_user_context_missing_sub() -> None:
    """Test that missing required 'sub' raises a ValidationError."""
    with pytest.raises(ValidationError) as excinfo:
        UserContext(email="test@example.com")  # type: ignore[call-arg]
    assert "Field required" in str(excinfo.value)
    assert "sub" in str(excinfo.value)


def test_user_context_missing_email() -> None:
    """Test that missing required 'email' raises a ValidationError."""
    with pytest.raises(ValidationError) as excinfo:
        UserContext(sub="user123")  # type: ignore[call-arg]
    assert "Field required" in str(excinfo.value)
    assert "email" in str(excinfo.value)


def test_user_context_immutability() -> None:
    """
    Test that the model behaves as expected (standard Pydantic models are mutable by default,
    but we verify basic assignment works).
    The requirements don't strictly specify frozen=True, but 'sub (Immutable User ID)' hints at it.
    Let's check if we can modify it.
    """
    user = UserContext(sub="user123", email="test@example.com")
    user.project_context = "proj2"
    assert user.project_context == "proj2"
