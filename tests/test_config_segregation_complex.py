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
Tests for complex scenarios involving configuration segregation.
"""

import os
from unittest.mock import AsyncMock, patch

import pytest

from coreason_identity.config import CoreasonClientConfig, CoreasonVerifierConfig
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.manager import IdentityManager


class TestConfigSegregationComplex:
    def test_mixed_usage_simultaneous_managers(self) -> None:
        """
        Complex Scenario: An application using two managers.
        One for verifying incoming tokens (API Gateway role).
        One for acting as a client (Service-to-Service role).
        """
        verifier_config = CoreasonVerifierConfig(domain="auth.verifier.com", audience="api://verifier")
        client_config = CoreasonClientConfig(
            domain="auth.client.com", audience="api://client", client_id="service-client"
        )

        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
            patch("coreason_identity.manager.DeviceFlowClient") as MockDeviceClient,
        ):
            verifier_manager = IdentityManager(verifier_config)
            client_manager = IdentityManager(client_config)

            # Verifier Manager: Should fail device flow
            with pytest.raises(CoreasonIdentityError, match="Device login requires CoreasonClientConfig"):
                verifier_manager.start_device_login(scope="openid profile email")

            # Client Manager: Should succeed (mocked)
            MockDeviceClient.return_value.initiate_flow = AsyncMock(return_value="mock_flow")
            client_manager.start_device_login(scope="openid profile email")
            assert MockDeviceClient.called

    def test_env_var_loading_isolation(self) -> None:
        """
        Complex Scenario: Loading configs from environment variables.
        Ensures that CoreasonVerifierConfig ignores 'COREASON_AUTH_CLIENT_ID' if present,
        but CoreasonClientConfig picks it up.
        Actually, Pydantic with extra='forbid' might RAISE error if env var is present but field is not.
        Let's verify the behavior. Ideally, environment variables that map to non-existent fields are
        IGNORED by default in pydantic-settings, UNLESS configured otherwise. But 'extra=forbid' usually
        applies to init kwargs, not necessarily env vars depending on config.
        """
        env_vars = {
            "COREASON_AUTH_DOMAIN": "env.auth.com",
            "COREASON_AUTH_AUDIENCE": "env-audience",
            "COREASON_AUTH_PII_SALT": "env-salt",
            "COREASON_AUTH_CLIENT_ID": "env-client-id",
            "COREASON_AUTH_HTTP_TIMEOUT": "5.0",
        }

        with patch.dict(os.environ, env_vars):
            # 1. Initialize Client Config - Should pick up client_id
            client_cfg = CoreasonClientConfig()
            assert client_cfg.domain == "env.auth.com"
            assert client_cfg.client_id == "env-client-id"

            # 2. Initialize Verifier Config - Should IGNORE client_id (standard behavior) or Fail?
            # By default pydantic-settings ignores extra env vars unless `extra='forbid'` is set on the
            # model AND it applies to env settings. CoreasonVerifierConfig has
            # `model_config = SettingsConfigDict(..., case_sensitive=False)`.
            # It inherits from BaseSettings.
            # Default for BaseSettings is usually `extra='ignore'`.

            verifier_cfg = CoreasonVerifierConfig()
            assert verifier_cfg.domain == "env.auth.com"
            assert not hasattr(verifier_cfg, "client_id")
            # If it didn't crash, it ignored the extra env var, which is correct for "Least Privilege" runtime loading.

    def test_runtime_upgrade_simulation(self) -> None:
        """
        Complex Scenario: Simulating a service that starts as a Verifier, then realizes it needs to act as a Client.
        It must re-initialize IdentityManager with a Client Config.
        """
        # Phase 1: Verifier
        verifier_config = CoreasonVerifierConfig(domain="d", audience="a")

        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
        ):
            manager = IdentityManager(verifier_config)

            # Action: Try to login -> Fail
            with pytest.raises(CoreasonIdentityError):
                manager.start_device_login(scope="openid profile email")

            # Phase 2: "Upgrade" - Must create NEW config and NEW manager
            # We cannot just set manager._async.config because runtime checks might depend on other things initialized?
            # Actually, IdentityManagerAsync stores self.config.
            # Technically one *could* hack it: manager._async.config = client_config
            # But the correct pattern is re-instantiation.

            client_config = CoreasonClientConfig(domain="d", audience="a", client_id="new-cid")

            # Re-init manager
            # Note: In a real app, you'd likely replace the dependency in your container.
            new_manager = IdentityManager(client_config)

            # Verify new capabilities
            with patch("coreason_identity.manager.DeviceFlowClient") as MockDC:
                MockDC.return_value.initiate_flow = AsyncMock(return_value="flow")
                new_manager.start_device_login(scope="openid profile email")
                assert MockDC.called
