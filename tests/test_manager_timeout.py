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

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.manager import IdentityManager


def test_manager_uses_configured_timeout() -> None:
    """
    Verify that IdentityManagerAsync initializes httpx.AsyncClient
    with the http_timeout from configuration.
    """
    timeout_value = 10.5
    config = CoreasonIdentityConfig(
        domain="test.auth0.com",
        audience="test",
        http_timeout=timeout_value,
    )

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator"),
        patch("coreason_identity.manager.IdentityMapper"),
        patch("httpx.AsyncClient") as MockClient,
    ):
        IdentityManager(config)

        # IdentityManager -> IdentityManagerAsync -> httpx.AsyncClient
        MockClient.assert_called_with(timeout=timeout_value)
