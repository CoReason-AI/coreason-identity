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
import time
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from authlib.jose import JsonWebKey, jwt
from pydantic import SecretStr

from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestPiiSecurity:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        provider = Mock(spec=OIDCProvider)
        provider.get_jwks = AsyncMock()
        provider.get_issuer = AsyncMock(return_value="https://valid-issuer.com")
        return provider

    @pytest.fixture
    def key_pair(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @pytest.fixture
    def jwks(self, key_pair: Any) -> dict[str, Any]:
        return {"keys": [key_pair.as_dict(private=False)]}

    def create_token(self, key: Any, claims: dict[str, Any], headers: dict[str, Any] | None = None) -> bytes:
        if headers is None:
            headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
        return jwt.encode(headers, claims, key)

    def test_hmac_anonymization(self, mock_oidc_provider: Mock) -> None:
        """
        Test Case 1 (HMAC Verification):
        - Initialize TokenValidator with a known salt.
        - Anonymize a user ID.
        - Assert that the result matches the expected HMAC-SHA256 hex digest.
        - Assert that the result is NOT the plain SHA-256 hash.
        """
        salt = "test-salt"
        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="aud",
            pii_salt=SecretStr(salt),
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256"],
        )

        user_id = "user123"
        anonymized = validator._anonymize(user_id)

        # Expected HMAC-SHA256
        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()

        # Plain SHA-256 (unsafe)
        unsafe_hash = hashlib.sha256(user_id.encode("utf-8")).hexdigest()

        assert anonymized == expected
        assert anonymized != unsafe_hash

    @pytest.mark.asyncio
    async def test_telemetry_protection(self, mock_oidc_provider: Mock, key_pair: Any, jwks: dict[str, Any]) -> None:
        """
        Test Case 2 (Telemetry Protection):
        - Mock the trace.get_tracer or check the span attributes.
        - Call validate_token.
        - Assert that the span attribute "enduser.id" contains the hashed value, not the raw ID.
        """
        salt = "test-salt"
        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="aud",
            pii_salt=SecretStr(salt),
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256"],
        )
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        user_id = "user123"
        claims = {
            "sub": user_id,
            "aud": "aud",
            "iss": "https://valid-issuer.com",
            "exp": now + 3600,
            "iat": now,
        }
        token = self.create_token(key_pair, claims)
        token_str = token.decode("utf-8")

        # Mock the tracer and span
        with patch("coreason_identity.validator.tracer") as mock_tracer:
            mock_span = Mock()
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

            await validator.validate_token(token_str)

            # Calculate expected anonymized ID
            expected_anonymized = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()

            # Verify set_attribute was called with the anonymized ID
            mock_span.set_attribute.assert_any_call("enduser.id", expected_anonymized)

            # Verify raw ID was NOT used
            with pytest.raises(AssertionError):
                mock_span.set_attribute.assert_any_call("enduser.id", user_id)
