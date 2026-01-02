# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InsufficientPermissionsError,
    InvalidAudienceError,
    SignatureVerificationError,
    TokenExpiredError,
)


def test_exception_hierarchy():
    """Test that all custom exceptions inherit from CoreasonIdentityError."""
    assert issubclass(TokenExpiredError, CoreasonIdentityError)
    assert issubclass(InvalidAudienceError, CoreasonIdentityError)
    assert issubclass(SignatureVerificationError, CoreasonIdentityError)
    assert issubclass(InsufficientPermissionsError, CoreasonIdentityError)


def test_exception_instantiation():
    """Test that exceptions can be instantiated."""
    err = TokenExpiredError("Token expired")
    assert str(err) == "Token expired"
