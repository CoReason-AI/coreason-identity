# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from coreason_identity.config import CoreasonIdentityConfig


def test_config_loading() -> None:
    """Test loading configuration from environment variables."""
    with patch.dict(
        os.environ,
        {
            "COREASON_AUTH_DOMAIN": "test.auth0.com",
            "COREASON_AUTH_AUDIENCE": "api://test",
            "COREASON_AUTH_PII_SALT": "env-salt",
        },
    ):
        config = CoreasonIdentityConfig()
        assert config.domain == "test.auth0.com"
        assert config.audience == "api://test"
        assert config.pii_salt.get_secret_value() == "env-salt"


def test_config_case_insensitive() -> None:
    """Test that environment variables are case-insensitive (pydantic-settings default behavior)."""
    with patch.dict(
        os.environ,
        {
            "coreason_auth_domain": "lower.auth0.com",
            "COREASON_AUTH_AUDIENCE": "api://lower",
            "coreason_auth_pii_salt": "lower-salt",
        },
    ):
        config = CoreasonIdentityConfig()
        assert config.domain == "lower.auth0.com"
        assert config.audience == "api://lower"
        assert config.pii_salt.get_secret_value() == "lower-salt"


def test_config_domain_normalization() -> None:
    """Test that domain is normalized to hostname only."""
    # Simple hostname
    c1 = CoreasonIdentityConfig(domain="test.com", audience="aud", pii_salt="test-salt")
    assert c1.domain == "test.com"

    # With https://
    c2 = CoreasonIdentityConfig(domain="https://test.com", audience="aud", pii_salt="test-salt")
    assert c2.domain == "test.com"

    # With trailing slash
    c3 = CoreasonIdentityConfig(domain="test.com/", audience="aud", pii_salt="test-salt")
    assert c3.domain == "test.com"

    # With path (should strip path)
    c4 = CoreasonIdentityConfig(domain="https://test.com/auth", audience="aud", pii_salt="test-salt")
    assert c4.domain == "test.com"


def test_missing_pii_salt_raises_error() -> None:
    """Test that initialization fails if pii_salt is missing."""
    with pytest.raises(ValidationError) as exc_info:
        CoreasonIdentityConfig(domain="test.com", audience="aud")

    errors = exc_info.value.errors()
    assert any(error["loc"] == ("pii_salt",) for error in errors)
