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
Tests for edge cases in config segregation.
"""

from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from coreason_identity.config import CoreasonClientConfig, CoreasonVerifierConfig
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.manager import IdentityManager


class TestConfigSegregationEdgeCases:
    def test_verifier_config_rejects_client_id(self) -> None:
        """
        Edge Case: Attempting to pass 'client_id' to CoreasonVerifierConfig should fail validation.
        This confirms strict model configuration (extra='forbid').
        """
        with pytest.raises(ValidationError) as exc_info:
            CoreasonVerifierConfig(
                domain="test.auth0.com",
                audience="aud",
                client_id="unexpected_client_id",  # type: ignore[call-arg]
            )
        assert "Extra inputs are not permitted" in str(exc_info.value)
        assert "client_id" in str(exc_info.value)

    def test_manager_initialized_with_verifier_rejects_device_flow(self) -> None:
        """
        Edge Case: IdentityManager initialized with Verifier config MUST raise CoreasonIdentityError
        when attempting device flow methods.
        """
        config = CoreasonVerifierConfig(domain="test.auth0.com", audience="aud")

        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
        ):
            manager = IdentityManager(config)

            with pytest.raises(CoreasonIdentityError, match="Device login requires CoreasonClientConfig"):
                manager.start_device_login(scope="openid profile email")

            # Mock flow object for await_device_token call
            mock_flow = type("DeviceFlowResponse", (), {})()
            with pytest.raises(CoreasonIdentityError, match="Device login requires CoreasonClientConfig"):
                manager.await_device_token(mock_flow)

    def test_manager_initialized_with_client_allows_device_flow(self) -> None:
        """
        Edge Case: IdentityManager initialized with Client config should proceed (mocking network).
        """
        config = CoreasonClientConfig(domain="test.auth0.com", audience="aud", client_id="cid")

        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
            patch("coreason_identity.manager.DeviceFlowClient") as MockDeviceClient,
        ):
            manager = IdentityManager(config)

            # Should NOT raise CoreasonIdentityError about config type
            # It might raise network errors if we don't mock perfectly, but we just check it passes the type check
            MockDeviceClient.return_value.initiate_flow = AsyncMock(return_value="mock_flow")

            manager.start_device_login(scope="openid profile email")
            assert MockDeviceClient.called

    def test_inheritance_semantics(self) -> None:
        """
        Edge Case: CoreasonClientConfig MUST be an instance of CoreasonVerifierConfig.
        This ensures Liskov Substitution Principle for verification logic.
        """
        client_config = CoreasonClientConfig(domain="d", audience="a", client_id="c")
        assert isinstance(client_config, CoreasonVerifierConfig)
        assert client_config.client_id == "c"

        verifier_config = CoreasonVerifierConfig(domain="d", audience="a")
        assert not isinstance(verifier_config, CoreasonClientConfig)
        assert not hasattr(verifier_config, "client_id")

    def test_client_config_without_client_id_fails(self) -> None:
        """
        Edge Case: CoreasonClientConfig requires client_id.
        """
        with pytest.raises(ValidationError) as exc_info:
            CoreasonClientConfig(domain="d", audience="a")
        assert "Field required" in str(exc_info.value)
        assert "client_id" in str(exc_info.value)
