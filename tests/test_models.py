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
    user = UserContext(sub="user123", email="test@example.com", project_context="proj1", permissions=["read"])
    assert user.sub == "user123"
    assert user.email == "test@example.com"
    assert user.project_context == "proj1"
    assert user.permissions == ["read"]


def test_user_context_defaults() -> None:
    user = UserContext(sub="user123", email="test@example.com")
    assert user.sub == "user123"
    assert user.email == "test@example.com"
    assert user.project_context is None
    assert user.permissions == []


def test_user_context_invalid_email() -> None:
    with pytest.raises(ValidationError):
        UserContext(sub="user123", email="not-an-email")


def test_user_context_missing_fields() -> None:
    with pytest.raises(ValidationError):
        # Missing email
        UserContext(sub="user123")  # type: ignore[call-arg]
