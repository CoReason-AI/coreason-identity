# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import AsyncMock, Mock, patch

import pytest
from authlib.jose.errors import BadSignatureError
from pydantic import SecretStr

from coreason_identity.exceptions import (
    CoreasonIdentityError,
    SignatureVerificationError,
)
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestTokenValidatorRetryLogic:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        provider = Mock(spec=OIDCProvider)
        provider.get_jwks = AsyncMock()
        return provider

    @pytest.fixture
    def validator(self, mock_oidc_provider: Mock) -> TokenValidator:
        return TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://valid-issuer.com",
            pii_salt=SecretStr("test-salt"),
            allowed_algorithms=["RS256"],
        )

    @pytest.mark.asyncio
    async def test_retry_success_after_jwks_refresh(self, validator: TokenValidator, mock_oidc_provider: Mock) -> None:
        # First call to decode fails with BadSignatureError
        # Second call (after refresh) succeeds
        mock_jwks_initial = {"keys": [{"kid": "old"}]}
        mock_jwks_refreshed = {"keys": [{"kid": "new"}]}
        mock_oidc_provider.get_jwks.side_effect = [mock_jwks_initial, mock_jwks_refreshed]

        mock_claims = Mock()
        mock_claims.validate = Mock()
        mock_claims.__iter__ = Mock(return_value=iter([("sub", "user123")]))

        with patch.object(validator.jwt, "decode") as mock_decode:
            mock_decode.side_effect = [BadSignatureError(), mock_claims]

            result = await validator.validate_token("some.token")

            assert result["sub"] == "user123"
            assert mock_oidc_provider.get_jwks.call_count == 2
            mock_oidc_provider.get_jwks.assert_any_call()
            mock_oidc_provider.get_jwks.assert_any_call(force_refresh=True)

    @pytest.mark.asyncio
    async def test_retry_failure_bad_signature_after_refresh(
        self, validator: TokenValidator, mock_oidc_provider: Mock
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = {"keys": []}

        with (
            patch.object(validator.jwt, "decode", side_effect=BadSignatureError()),
            pytest.raises(SignatureVerificationError, match="Invalid signature"),
        ):
            await validator.validate_token("some.token")

        assert mock_oidc_provider.get_jwks.call_count == 2
        mock_oidc_provider.get_jwks.assert_any_call(force_refresh=True)

    @pytest.mark.asyncio
    async def test_retry_failure_value_error_after_refresh(
        self, validator: TokenValidator, mock_oidc_provider: Mock
    ) -> None:
        mock_oidc_provider.get_jwks.return_value = {"keys": []}

        with (
            patch.object(validator.jwt, "decode", side_effect=ValueError("Invalid key")),
            pytest.raises(CoreasonIdentityError, match="Unexpected ValueError during validation"),
        ):
            await validator.validate_token("some.token")

        assert mock_oidc_provider.get_jwks.call_count == 2
        mock_oidc_provider.get_jwks.assert_any_call(force_refresh=True)
