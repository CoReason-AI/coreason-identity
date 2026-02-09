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

from coreason_identity.config import CoreasonVerifierConfig
from coreason_identity.identity_mapper import RawIdPClaims


def test_identity_mapper_list_normalization() -> None:
    """
    Test edge cases for list normalization in RawIdPClaims.
    """
    # 1. None groups -> []
    raw = RawIdPClaims(sub="u", email="e@e.com", groups=None)
    assert raw.groups == []

    # 2. String groups -> [str]
    raw2 = RawIdPClaims(sub="u", email="e@e.com", groups="group1")
    assert raw2.groups == ["group1"]

    # 3. List with None -> filtered
    raw3 = RawIdPClaims(sub="u", email="e@e.com", groups=["g1", None, "g2"])
    assert raw3.groups == ["g1", "g2"]

    # 4. Invalid type -> [] (if ensure_list_of_strings handles it, checking implementation)
    # The implementation handles list|tuple or str. Int falls through to return []?
    # Let's check ensure_list_of_strings in identity_mapper.py
    # if isinstance(v, list | tuple): ... else return []
    # So int returns []
    raw4 = RawIdPClaims(sub="u", email="e@e.com", groups=123)
    assert raw4.groups == []


@pytest.mark.asyncio
async def test_manager_auth_header_too_long() -> None:
    """Test rejection of overly long auth header."""
    from unittest.mock import patch

    from coreason_identity.config import CoreasonVerifierConfig
    from coreason_identity.exceptions import InvalidTokenError
    from coreason_identity.manager import IdentityManager

    config = CoreasonVerifierConfig(
        domain="d", audience="a", issuer="https://i", pii_salt="s", allowed_algorithms=["HS256"], http_timeout=5.0
    )

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
    ):
        manager = IdentityManager(config)
        long_header = "Bearer " + "a" * 5000

        with pytest.raises(InvalidTokenError, match="Authorization header is too long"):
            await manager.validate_token(long_header)
