"""
Extended edge case tests for implicit issuer trust mitigation.
Focuses on strict string matching, protocol mismatches, and subdomain attacks.
Using real JWT signing/decoding to verify Authlib integration.
"""

from typing import Any
from unittest.mock import AsyncMock

import pytest
from authlib.jose import JsonWebKey, jwt
from pydantic import SecretStr

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.validator import TokenValidator


class TestIssuerTrustExtended:
    @pytest.fixture
    def mock_oidc(self) -> AsyncMock:
        mock = AsyncMock()
        mock.get_jwks = AsyncMock()
        return mock

    @pytest.fixture
    def key_pair(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @pytest.fixture
    def jwks(self, key_pair: Any) -> dict[str, Any]:
        return {"keys": [key_pair.as_dict(private=False)]}

    def create_token(self, key: Any, claims: dict[str, Any]) -> str:
        headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
        return jwt.encode(headers, claims, key).decode("utf-8")

    @pytest.mark.asyncio
    async def test_exact_string_matching_trailing_slash(
        self, mock_oidc: AsyncMock, key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Test Case 1: Exact string matching variations.
        Configured issuer 'https://a.com' should NOT match token issuer 'https://a.com/'
        """
        mock_oidc.get_jwks.return_value = jwks

        # Scenario A: Config has NO trailing slash, Token HAS trailing slash
        issuer_config = "https://a.com"
        issuer_token = "https://a.com/"

        validator = TokenValidator(
            oidc_provider=mock_oidc,
            audience="aud",
            issuer=issuer_config,
            pii_salt=SecretStr("test-salt"),
            allowed_algorithms=["RS256"],
        )

        token = self.create_token(key_pair, {"sub": "u", "iss": issuer_token, "aud": "aud", "exp": 9999999999})

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_exact_string_matching_no_trailing_slash(
        self, mock_oidc: AsyncMock, key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Scenario B: Config HAS trailing slash, Token has NO trailing slash.
        """
        mock_oidc.get_jwks.return_value = jwks

        issuer_config = "https://a.com/"
        issuer_token = "https://a.com"

        validator = TokenValidator(
            oidc_provider=mock_oidc,
            audience="aud",
            issuer=issuer_config,
            pii_salt=SecretStr("test-salt"),
            allowed_algorithms=["RS256"],
        )

        token = self.create_token(key_pair, {"sub": "u", "iss": issuer_token, "aud": "aud", "exp": 9999999999})

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_subdomain_attack_prefix(self, mock_oidc: AsyncMock, key_pair: Any, jwks: dict[str, Any]) -> None:
        """
        Test Case 2: Subdomain/Prefix attacks.
        Config: https://auth.company.com
        Token: https://auth.company.com.attacker.com
        """
        mock_oidc.get_jwks.return_value = jwks

        issuer_config = "https://auth.company.com"
        issuer_token = "https://auth.company.com.attacker.com"

        validator = TokenValidator(
            oidc_provider=mock_oidc,
            audience="aud",
            issuer=issuer_config,
            pii_salt=SecretStr("test-salt"),
            allowed_algorithms=["RS256"],
        )

        token = self.create_token(key_pair, {"sub": "u", "iss": issuer_token, "aud": "aud", "exp": 9999999999})

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_subdomain_attack_suffix(self, mock_oidc: AsyncMock, key_pair: Any, jwks: dict[str, Any]) -> None:
        """
        Test Case 2b: Suffix attack.
        Config: https://company.com
        Token: https://auth.company.com
        """
        mock_oidc.get_jwks.return_value = jwks

        issuer_config = "https://company.com"
        issuer_token = "https://auth.company.com"

        validator = TokenValidator(
            oidc_provider=mock_oidc,
            audience="aud",
            issuer=issuer_config,
            pii_salt=SecretStr("test-salt"),
            allowed_algorithms=["RS256"],
        )

        token = self.create_token(key_pair, {"sub": "u", "iss": issuer_token, "aud": "aud", "exp": 9999999999})

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_protocol_mismatch(self, mock_oidc: AsyncMock, key_pair: Any, jwks: dict[str, Any]) -> None:
        """
        Test Case 3: HTTP vs HTTPS mismatch explicit check.
        """
        mock_oidc.get_jwks.return_value = jwks

        issuer_config = "https://auth.com/"
        issuer_token = "http://auth.com/"

        validator = TokenValidator(
            oidc_provider=mock_oidc,
            audience="aud",
            issuer=issuer_config,
            pii_salt=SecretStr("test-salt"),
            allowed_algorithms=["RS256"],
        )

        token = self.create_token(key_pair, {"sub": "u", "iss": issuer_token, "aud": "aud", "exp": 9999999999})

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            await validator.validate_token(token)
