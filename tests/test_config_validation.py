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


def test_config_strict_domain_validation() -> None:
    """
    Test that the domain validator rejects URLs.
    """
    # Valid domain
    config = CoreasonVerifierConfig(
        domain="auth.coreason.com",
        audience="aud",
        pii_salt="salt",
        http_timeout=5.0,
        allowed_algorithms=["RS256"],
    )
    assert config.domain == "auth.coreason.com"
    # Issuer should be derived correctly
    assert config.issuer == "https://auth.coreason.com/"

    # Invalid: Contains scheme
    with pytest.raises(ValidationError, match="Domain must be a hostname"):
        CoreasonVerifierConfig(
            domain="https://auth.coreason.com",
            audience="aud",
            pii_salt="salt",
            http_timeout=5.0,
            allowed_algorithms=["RS256"],
        )

    # Invalid: Contains path
    with pytest.raises(ValidationError, match="Domain must be a hostname"):
        CoreasonVerifierConfig(
            domain="auth.coreason.com/path",
            audience="aud",
            pii_salt="salt",
            http_timeout=5.0,
            allowed_algorithms=["RS256"],
        )

    # Invalid: Contains trailing slash
    with pytest.raises(ValidationError, match="Domain must be a hostname"):
        CoreasonVerifierConfig(
            domain="auth.coreason.com/",
            audience="aud",
            pii_salt="salt",
            http_timeout=5.0,
            allowed_algorithms=["RS256"],
        )
