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


def test_coreason_identity_error() -> None:
    exc = CoreasonIdentityError("test")
    assert str(exc) == "test"
    assert isinstance(exc, Exception)


def test_token_expired_error() -> None:
    exc = TokenExpiredError("expired")
    assert str(exc) == "expired"
    assert isinstance(exc, CoreasonIdentityError)


def test_invalid_audience_error() -> None:
    exc = InvalidAudienceError("invalid audience")
    assert str(exc) == "invalid audience"
    assert isinstance(exc, CoreasonIdentityError)


def test_signature_verification_error() -> None:
    exc = SignatureVerificationError("bad signature")
    assert str(exc) == "bad signature"
    assert isinstance(exc, CoreasonIdentityError)


def test_insufficient_permissions_error() -> None:
    exc = InsufficientPermissionsError("denied")
    assert str(exc) == "denied"
    assert isinstance(exc, CoreasonIdentityError)
