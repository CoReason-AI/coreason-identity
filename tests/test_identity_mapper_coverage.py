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
Tests for IdentityMapper coverage.
"""

from unittest.mock import patch

import pytest

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.identity_mapper import IdentityMapper


class TestIdentityMapperCoverage:
    def test_map_claims_unexpected_error(self) -> None:
        """Test line 109: Generic exception handling."""
        mapper = IdentityMapper()

        # Force a generic exception inside map_claims by mocking RawIdPClaims constructor
        # or by passing an object that causes failure in a way not caught by ValidationError
        # Mocking RawIdPClaims is easiest.

        with patch("coreason_identity.identity_mapper.RawIdPClaims", side_effect=Exception("Boom")):
            with pytest.raises(CoreasonIdentityError, match="Identity mapping error: Boom"):
                mapper.map_claims({"sub": "u", "email": "e@e.com"})
