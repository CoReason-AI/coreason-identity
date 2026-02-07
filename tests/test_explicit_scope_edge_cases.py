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
Tests for explicit scope enforcement edge cases and complex scenarios.
"""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from coreason_identity.config import CoreasonClientConfig
from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.manager import IdentityManager, IdentityManagerAsync
from coreason_identity.models import DeviceFlowResponse

# Mocks
MOCK_DOMAIN = "test.auth0.com"
MOCK_AUDIENCE = "test-audience"
MOCK_CLIENT_ID = "test-client-id"


@pytest.fixture
def config() -> CoreasonClientConfig:
    return CoreasonClientConfig(domain=MOCK_DOMAIN, audience=MOCK_AUDIENCE, client_id=MOCK_CLIENT_ID)


class TestExplicitScopeEdgeCases:
    @pytest.mark.asyncio
    async def test_start_device_login_whitespace_scope(self, config: CoreasonClientConfig) -> None:
        """
        Edge Case: Verify that whitespace-only scope strings are rejected.
        """
        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
        ):
            async with IdentityManagerAsync(config) as manager:
                with pytest.raises(ValueError, match="Scope must be explicitly provided"):
                    await manager.start_device_login(scope="   ")

    @pytest.mark.asyncio
    async def test_start_device_login_empty_scope(self, config: CoreasonClientConfig) -> None:
        """
        Edge Case: Verify that empty scope string is rejected.
        """
        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
        ):
            async with IdentityManagerAsync(config) as manager:
                with pytest.raises(ValueError, match="Scope must be explicitly provided"):
                    await manager.start_device_login(scope="")

    def test_device_flow_client_init_scope_validation(self) -> None:
        """
        Edge Case: Verify DeviceFlowClient accepts empty scope if passed directly?
        Actually, DeviceFlowClient constructor just takes a string. It doesn't validate strictly itself,
        but the Manager wrapper does.
        However, let's verify it accepts what is passed, as it's a lower-level component.
        """
        client = AsyncMock(spec=httpx.AsyncClient)
        # Should NOT raise error in constructor, even if scope is empty string (technically allowed by type system)
        # But Manager enforces policy.
        df_client = DeviceFlowClient("cid", "https://idp", client, scope="")
        assert df_client.scope == ""


class TestComplexScopeScenarios:
    @pytest.mark.asyncio
    async def test_concurrent_device_logins_different_scopes(self, config: CoreasonClientConfig) -> None:
        """
        Complex Scenario: Simulate concurrent login requests (if manager supported it) or sequential
        re-use with different scopes to ensure no cross-contamination.
        Note: IdentityManager instance shares `self.device_client`. If we call start_device_login again,
        it overwrites `self.device_client`.
        """
        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
            patch("coreason_identity.manager.DeviceFlowClient") as MockClient,
        ):
            # We need separate mock instances for separate calls ideally, but MockClient() returns same mock
            # unless side_effect is used.
            # Let's use side_effect to return distinct mocks
            mock_client_1 = AsyncMock(spec=DeviceFlowClient)
            mock_client_1.initiate_flow.return_value = DeviceFlowResponse(
                device_code="d1", user_code="u1", verification_uri="v1", expires_in=10, interval=1
            )
            mock_client_2 = AsyncMock(spec=DeviceFlowClient)
            mock_client_2.initiate_flow.return_value = DeviceFlowResponse(
                device_code="d2", user_code="u2", verification_uri="v2", expires_in=10, interval=1
            )

            MockClient.side_effect = [mock_client_1, mock_client_2]

            async with IdentityManagerAsync(config) as manager:
                # 1. Start flow A with scope A
                resp1 = await manager.start_device_login(scope="scope:A")
                assert resp1.user_code == "u1"
                MockClient.assert_called_with(
                    client_id=MOCK_CLIENT_ID,
                    idp_url=f"https://{MOCK_DOMAIN}",
                    client=manager._client,
                    scope="scope:A",
                )

                # 2. Start flow B with scope B (should re-init client)
                resp2 = await manager.start_device_login(scope="scope:B")
                assert resp2.user_code == "u2"
                # Check most recent call
                call_args = MockClient.call_args
                assert call_args.kwargs["scope"] == "scope:B"

    def test_sync_manager_scope_propagation(self, config: CoreasonClientConfig) -> None:
        """
        Complex Scenario: Verify Sync Facade correctly propagates whitespace error.
        """
        with (
            patch("coreason_identity.manager.OIDCProvider"),
            patch("coreason_identity.manager.TokenValidator"),
            patch("coreason_identity.manager.IdentityMapper"),
        ):
            manager = IdentityManager(config)
            with pytest.raises(ValueError, match="Scope must be explicitly provided"):
                manager.start_device_login(scope="   ")
