"""
Tests for explicit issuer trust mitigation.
Verifies that the issuer is correctly configured and enforced.
"""

from typing import Any
from pydantic import SecretStr
from unittest.mock import AsyncMock, patch

import pytest

from coreason_identity.config import CoreasonVerifierConfig
from coreason_identity.validator import TokenValidator


class TestIssuerTrust:
    def test_config_derives_issuer_from_domain(self) -> None:
        """
        Test Case 1: Config derivation.
        Initialize CoreasonVerifierConfig(domain="auth.example.com") (no issuer).
        Assert config.issuer == "https://auth.example.com/".
        """
        config = CoreasonVerifierConfig(domain="auth.example.com", audience="aud")
        assert config.issuer == "https://auth.example.com/"

    def test_config_explicit_issuer_override(self) -> None:
        """
        Test Case 2: Explicit override.
        Initialize CoreasonVerifierConfig(domain="auth.example.com", issuer="https://other.com").
        Assert config.issuer == "https://other.com".
        """
        config = CoreasonVerifierConfig(domain="auth.example.com", audience="aud", issuer="https://other.com")
        assert config.issuer == "https://other.com"

    @pytest.mark.asyncio
    async def test_validator_enforces_configured_issuer(self) -> None:
        """
        Test Case 3: Validator Enforcement.
        Initialize TokenValidator with issuer="https://trustworthy.com".
        Mock OIDCProvider.get_issuer() to return "https://malicious.com".
        Attempt to validate a token.
        Assert that the validator uses "https://trustworthy.com" for the iss claim check.
        """
        # Mock OIDCProvider
        mock_oidc = AsyncMock()
        # Mock JWKS to return valid keys for signature check
        mock_oidc.get_jwks.return_value = {"keys": []}
        # Mock get_issuer to return malicious issuer (should be ignored)
        mock_oidc.get_issuer.return_value = "https://malicious.com"

        expected_issuer = "https://trustworthy.com"
        validator = TokenValidator(oidc_provider=mock_oidc, audience="aud", issuer=expected_issuer, pii_salt=SecretStr("test-salt"), allowed_algorithms=["RS256"])

        # Mock JWT decode to avoid actual crypto
        # We want to verify that claims_options['iss']['value'] == expected_issuer
        with patch.object(validator.jwt, "decode") as mock_decode:

            class MockClaims(dict[str, Any]):
                def validate(self, *args: Any, **kwargs: Any) -> None:
                    pass

            mock_decode.return_value = MockClaims({"sub": "some-user-id"})

            # Call validate_token
            await validator.validate_token("fake-token")

            # Verify decode was called with correct options
            assert mock_decode.called
            _, kwargs = mock_decode.call_args
            claims_options = kwargs.get("claims_options", {})

            assert "iss" in claims_options
            assert claims_options["iss"]["value"] == expected_issuer
            assert claims_options["iss"]["value"] != "https://malicious.com"
