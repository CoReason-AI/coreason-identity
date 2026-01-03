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
Custom exceptions for the coreason-identity package.
"""


class CoreasonIdentityError(Exception):
    """Base exception for all coreason-identity errors."""

    pass


class InvalidTokenError(CoreasonIdentityError):
    """
    Raised when the token is invalid (expired, bad signature, wrong audience, etc.).
    Matches the example usage: `except InvalidTokenError:`.
    """

    pass


class TokenExpiredError(InvalidTokenError):
    """Raised when the provided token has expired."""

    pass


class InvalidAudienceError(InvalidTokenError):
    """Raised when the token's audience does not match the expected value."""

    pass


class SignatureVerificationError(InvalidTokenError):
    """Raised when the token's signature cannot be verified."""

    pass


class InsufficientPermissionsError(CoreasonIdentityError):
    """Raised when the user does not have the required permissions."""

    pass
