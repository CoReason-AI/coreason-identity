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
Tests for Async Context propagation.
"""

import asyncio
from typing import Any

import pytest
from pydantic import SecretStr

from coreason_identity.async_context import get_current_user, set_current_user
from coreason_identity.models import UserContext


def create_user(user_id: str) -> UserContext:
    return UserContext(
        user_id=user_id,
        email=f"{user_id}@example.com",
        groups=[],
        scopes=[],
        downstream_token=SecretStr("token"),
    )


@pytest.mark.asyncio
async def test_context_isolation() -> None:
    """Test that context is isolated between concurrent tasks."""

    async def task(user_id: str, delay: float) -> str | None:
        user = create_user(user_id)
        set_current_user(user)
        await asyncio.sleep(delay)
        current = get_current_user()
        return current.user_id if current else None

    # Run two tasks concurrently with different users
    t1 = asyncio.create_task(task("user1", 0.1))
    t2 = asyncio.create_task(task("user2", 0.1))

    r1, r2 = await asyncio.gather(t1, t2)

    assert r1 == "user1"
    assert r2 == "user2"


@pytest.mark.asyncio
async def test_context_propagation() -> None:
    """Test that context propagates to child tasks (if using TaskGroup or similar)."""
    # Note: contextvars propagate to created tasks by default.

    user = create_user("parent")
    set_current_user(user)

    async def child_task() -> str | None:
        # Should see parent's context
        current = get_current_user()
        return current.user_id if current else None

    result = await asyncio.create_task(child_task())
    assert result == "parent"


@pytest.mark.asyncio
async def test_context_modification_in_child() -> None:
    """Test that modifying context in child does NOT affect parent."""
    user = create_user("parent")
    set_current_user(user)

    async def child_task() -> None:
        # Child changes context
        child_user = create_user("child")
        set_current_user(child_user)
        assert get_current_user().user_id == "child"

    await asyncio.create_task(child_task())

    # Parent should still see original
    assert get_current_user().user_id == "parent"


@pytest.mark.asyncio
async def test_context_clearing() -> None:
    """Test explicit clearing (setting to None)."""
    user = create_user("u1")
    set_current_user(user)
    assert get_current_user() is not None

    from coreason_identity.async_context import clear_current_user

    clear_current_user()
    assert get_current_user() is None
