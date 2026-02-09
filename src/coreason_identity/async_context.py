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
Async Context Management for request-scoped UserContext.
"""

from contextvars import ContextVar

from coreason_identity.models import UserContext

# ContextVar to store the current user context.
# Default is None.
_current_user: ContextVar[UserContext | None] = ContextVar("current_user", default=None)


def get_current_user() -> UserContext | None:
    """
    Retrieve the current user context from the async context.

    Returns:
        UserContext | None: The current user context, or None if not set.
    """
    return _current_user.get()


def set_current_user(user: UserContext) -> None:
    """
    Set the current user context for the async task.

    Args:
        user: The UserContext to set.
    """
    _current_user.set(user)


def clear_current_user() -> None:
    """
    Clear the current user context (reset to None).
    """
    _current_user.set(None)
