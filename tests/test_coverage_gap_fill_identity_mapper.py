# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import patch

import pytest

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.identity_mapper import IdentityMapper


def test_identity_mapper_unexpected_exception() -> None:
    """
    Test that generic exceptions during mapping are caught, logged, and re-raised as CoreasonIdentityError.
    This covers lines 119-120 in identity_mapper.py.
    """
    mapper = IdentityMapper()
    claims = {"sub": "user123", "email": "test@example.com"}

    # Mock RawIdPClaims to raise a generic RuntimeError
    with (
        patch("coreason_identity.identity_mapper.RawIdPClaims", side_effect=RuntimeError("Unexpected Boom")),
        pytest.raises(CoreasonIdentityError, match="Identity mapping error: Unexpected Boom"),
    ):
        mapper.map_claims(claims)
