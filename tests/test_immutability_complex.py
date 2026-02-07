# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import copy
import pickle
import threading
from typing import Any

import pytest
from pydantic import ValidationError

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.models import UserContext


class TestImmutabilityComplex:
    """
    Comprehensive tests for the immutability of data models.
    """

    @pytest.fixture
    def user_context(self) -> UserContext:
        return UserContext(
            user_id="user123",
            email="test@example.com",
            groups=("admin", "dev"),
            scopes=("read", "write"),
            claims={"dept": "engineering"},
        )

    def test_assignment_blocked(self, user_context: UserContext) -> None:
        """Test that field assignment raises ValidationError."""
        with pytest.raises(ValidationError):
            user_context.user_id = "hacker"

        with pytest.raises(ValidationError):
            user_context.email = "hacker@example.com"

        with pytest.raises(ValidationError):
            user_context.groups = ("hacker",)

    def test_deep_immutability_tuples(self, user_context: UserContext) -> None:
        """
        Test that collection fields are tuples and do not support mutation methods like .append().
        """
        assert isinstance(user_context.groups, tuple)
        assert isinstance(user_context.scopes, tuple)

        # Tuples do not have .append(), so this raises AttributeError
        with pytest.raises(AttributeError):
            user_context.groups.append("hacker")  # type: ignore

        with pytest.raises(AttributeError):
            user_context.scopes.append("admin")  # type: ignore

    def test_copy_on_write(self, user_context: UserContext) -> None:
        """Test the copy-on-write pattern using model_copy."""
        # Create a new version
        new_groups = user_context.groups + ("audit",)
        updated_user = user_context.model_copy(update={"groups": new_groups})

        # Verify new instance
        assert updated_user is not user_context
        assert updated_user.groups == ("admin", "dev", "audit")

        # Verify original is untouched
        assert user_context.groups == ("admin", "dev")

    def test_pickling_integrity(self, user_context: UserContext) -> None:
        """Test that pickling and unpickling preserves state and type."""
        pickled = pickle.dumps(user_context)
        unpickled = pickle.loads(pickled)

        assert unpickled == user_context
        assert isinstance(unpickled, UserContext)
        # Verify it's still frozen/immutable
        with pytest.raises(ValidationError):
            unpickled.user_id = "changed"

    def test_deepcopy_behavior(self, user_context: UserContext) -> None:
        """Test that deepcopy works correctly."""
        copied = copy.deepcopy(user_context)
        assert copied == user_context
        assert copied is not user_context

        # Verify mutation attempt on copy fails
        with pytest.raises(ValidationError):
            copied.user_id = "new"

    def test_threading_safety_read(self, user_context: UserContext) -> None:
        """
        Test concurrent read access.
        Since models are immutable, this is inherently safe, but we verify no oddities occur.
        """
        errors: list[Exception] = []

        def access_model() -> None:
            try:
                _ = user_context.user_id
                _ = user_context.groups
                # Try to mutate (should fail)
                try:
                    user_context.user_id = "race_condition"
                except ValidationError:
                    pass
                else:
                    raise AssertionError("Mutation succeeded in thread")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=access_model) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors occurred in threads: {errors}"

    def test_config_immutability(self) -> None:
        """Test that CoreasonIdentityConfig is also immutable."""
        config = CoreasonIdentityConfig(domain="example.com", audience="aud")

        with pytest.raises(ValidationError):
            config.domain = "malicious.com"

        # Check that internal mutation via _secret_ field access is also discouraged/blocked by pydantic logic
        # Pydantic doesn't block private attr set by default unless extra='forbid', but public attrs are frozen.
        with pytest.raises(ValidationError):
            config.audience = "new_aud"

    def test_claims_dict_immutability_limitation(self, user_context: UserContext) -> None:
        """
        Documenting the limitation: The 'claims' dict itself is mutable if accessed directly,
        but the field 'claims' cannot be reassigned.
        """
        # Reassignment is blocked
        with pytest.raises(ValidationError):
            user_context.claims = {}

        # However, because it is a standard dict, in-place mutation is technically possible
        # We acknowledge this limitation. The primary protection is against 'scopes' and 'groups'.
        user_context.claims["mutable"] = "true"
        assert user_context.claims["mutable"] == "true"
