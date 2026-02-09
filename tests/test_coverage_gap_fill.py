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


def test_config_https_enforcement() -> None:
    """
    Test that HTTP issuer raises ValueError.
    """
    with pytest.raises(ValidationError) as exc:
        CoreasonVerifierConfig(
            domain="auth.example.com",
            audience="aud",
            issuer="http://insecure.com",
            pii_salt="salt",
            allowed_algorithms=["RS256"],
            http_timeout=5.0,
        )
    assert "HTTPS is required for production" in str(exc.value)


def test_identity_mapper_list_normalization() -> None:
    """
    Test edge cases for list normalization in RawIdPClaims.
    """
    # 1. None groups/permissions -> []
    raw = RawIdPClaims(sub="u", email="e@e.com", groups=None, permissions=None)
    assert raw.groups == []
    assert raw.permissions == []

    # 2. String groups/permissions -> [str]
    raw2 = RawIdPClaims(sub="u", email="e@e.com", groups="group1", permissions="perm1")
    assert raw2.groups == ["group1"]
    assert raw2.permissions == ["perm1"]

    # 3. List with None -> filtered
    raw3 = RawIdPClaims(sub="u", email="e@e.com", groups=["g1", None, "g2"])
    assert raw3.groups == ["g1", "g2"]
