# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import hashlib
import hmac
from unittest.mock import Mock, patch

import pytest
from pydantic import SecretStr

from coreason_identity.config import CoreasonVerifierConfig
from coreason_identity.manager import IdentityManager
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestPiiAnonymizationComplexScenarios:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        return Mock(spec=OIDCProvider)

    def test_salt_rotation_simulation(self, mock_oidc_provider: Mock) -> None:
        """
        Complex Case 1: Salt Rotation Simulation.
        Instantiate two TokenValidators with different salts. Verify that the same User ID produces different hashes.
        """
        salt_a = "salt-v1"
        salt_b = "salt-v2"

        validator_a = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt_a))
        validator_b = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt_b))

        user_id = "user123"
        hash_a = validator_a._anonymize(user_id)
        hash_b = validator_b._anonymize(user_id)

        assert hash_a != hash_b

        # Verify correctness individually
        expected_a = hmac.new(salt_a.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()
        assert hash_a == expected_a

    def test_deterministic_output(self, mock_oidc_provider: Mock) -> None:
        """
        Complex Case 2: Deterministic Output.
        Verify that the same User ID + same Salt always produces the same hash across multiple calls.
        """
        salt = "stable-salt"
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt))

        user_id = "user123"

        # Call multiple times
        results = [validator._anonymize(user_id) for _ in range(100)]

        # All results should be identical
        assert all(r == results[0] for r in results)

    def test_config_integration(self) -> None:
        """
        Complex Case 3: Config Integration.
        Verify IdentityManager correctly propagates the salt from a complex config object to the validator.
        """
        custom_salt = "super-secret-salt-value"
        config = CoreasonVerifierConfig(
            domain="auth.example.com", audience="aud", pii_salt=SecretStr(custom_salt)
        )

        with (
            patch("coreason_identity.manager.OIDCProvider") as MockOIDC,
            patch("coreason_identity.manager.TokenValidator") as MockValidator,
        ):
            IdentityManager(config)

            # Check that TokenValidator was initialized with the custom salt
            MockOIDC.assert_called_once()
            MockValidator.assert_called_once()
            call_kwargs = MockValidator.call_args[1]
            assert call_kwargs["pii_salt"] == config.pii_salt
            assert call_kwargs["pii_salt"].get_secret_value() == custom_salt
