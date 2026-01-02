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

from coreason_identity.config import CoreasonIdentityConfig


def test_config_loading():
    """Test loading configuration from environment variables."""
    with patch.dict(os.environ, {
        "COREASON_AUTH_DOMAIN": "test.auth0.com",
        "COREASON_AUTH_AUDIENCE": "api://test",
    }):
        config = CoreasonIdentityConfig()
        assert config.domain == "test.auth0.com"
        assert config.audience == "api://test"


def test_config_case_insensitive():
    """Test that environment variables are case-insensitive (pydantic-settings default behavior)."""
    with patch.dict(os.environ, {
        "coreason_auth_domain": "lower.auth0.com",
        "COREASON_AUTH_AUDIENCE": "api://lower",
    }):
        config = CoreasonIdentityConfig()
        assert config.domain == "lower.auth0.com"
        assert config.audience == "api://lower"
