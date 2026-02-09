# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr

from coreason_identity.config import CoreasonClientConfig
from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.manager import IdentityManager
from coreason_identity.models import DeviceFlowResponse

# Mock data
MOCK_DOMAIN = "test.auth0.com"
MOCK_AUDIENCE = "test-audience"
MOCK_CLIENT_ID = "test-client-id"


class TestComplexScopeScenarios:
    @pytest.fixture
    def config(self) -> CoreasonClientConfig:
        return CoreasonClientConfig(
            domain=MOCK_DOMAIN,
            audience=MOCK_AUDIENCE,
            client_id=MOCK_CLIENT_ID,
            http_timeout=5.0,
            issuer=f"https://{MOCK_DOMAIN}/",
        )

    @pytest.mark.asyncio
    async def test_explicit_scope_validation_manager(self, config: CoreasonClientConfig) -> None:
        """
        Verify that manager rejects missing scopes before creating DeviceFlowClient.
        """
        with (
            patch("coreason_identity.manager.OIDCProvider"),
            # Validator is not initialized for client config, so patch is optional/ignored
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
        ):
            async with IdentityManager(config) as manager:
                # 1. Missing scope (None) -> Caught by type checker (now TypeError) or runtime if check exists
                # Since signature requires scope: str, calling without args is TypeError.
                # If we pass None (despite type hint), it should raise ValueError or similar if checked.
                # However, our updated manager expects str.
                # Let's test empty string.
                with pytest.raises(ValueError, match="Scope must be explicitly provided"):
                    await manager.start_device_login(scope="")

                # 2. Whitespace only -> ValueError
                with pytest.raises(ValueError, match="Scope must be explicitly provided"):
                    await manager.start_device_login(scope="   ")

    @pytest.mark.asyncio
    async def test_scope_propagation_to_client(self, config: CoreasonClientConfig) -> None:
        """
        Verify that the scope string is correctly passed to DeviceFlowClient.
        """
        target_scope = "openid profile custom:scope"

        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
            patch("coreason_identity.manager.DeviceFlowClient") as MockClient,
        ):
            mock_client_instance = MockClient.return_value
            mock_client_instance.initiate_flow = AsyncMock()

            async with IdentityManager(config) as manager:
                await manager.start_device_login(scope=target_scope)

                MockClient.assert_called_with(
                    client_id=MOCK_CLIENT_ID,
                    idp_url=f"https://{MOCK_DOMAIN}",
                    client=manager._client,
                    scope=target_scope,
                )

    @pytest.mark.asyncio
    async def test_concurrent_device_logins_different_scopes(self, config: CoreasonClientConfig) -> None:
        """
        Complex Scenario: Reuse with different scopes.
        Note: IdentityManager instance shares `self.device_client`. If we call start_device_login again,
        it reuses `self.device_client` which has the old scope.
        """
        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
            patch("coreason_identity.manager.DeviceFlowClient") as MockClient,
        ):
            mock_client_1 = AsyncMock(spec=DeviceFlowClient)
            mock_client_1.initiate_flow.return_value = DeviceFlowResponse(
                device_code="d1", user_code="u1", verification_uri="v1", expires_in=10, interval=1
            )

            # Only 1 client is created because we reuse it
            MockClient.side_effect = [mock_client_1]

            async with IdentityManager(config) as manager:
                # 1. Start flow A with scope A
                resp1 = await manager.start_device_login(scope="scope:A")
                assert resp1.user_code == "u1"
                MockClient.assert_called_once_with(
                    client_id=MOCK_CLIENT_ID,
                    idp_url=f"https://{MOCK_DOMAIN}",
                    client=manager._client,
                    scope="scope:A",
                )

                # 2. Start flow B with scope B (reuses client with scope A)
                resp2 = await manager.start_device_login(scope="scope:B")

                # Should return result from SAME client instance (mock_client_1)
                # And since mock_client_1 returns "u1", resp2.user_code is "u1".
                assert resp2.user_code == "u1"

                # Verify constructor was NOT called again
                assert MockClient.call_count == 1
