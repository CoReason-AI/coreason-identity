"""
Complex test cases for issuer trust.
Overlapping/Redundant scenarios involving concurrency and key rotation with issuer checks.
Using real JWT signing/decoding to verify Authlib integration.
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr
from authlib.jose import JsonWebKey, jwt

from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.validator import TokenValidator


class TestIssuerTrustComplex:
    @pytest.fixture
    def mock_oidc(self) -> AsyncMock:
        mock = AsyncMock()
        mock.get_jwks = AsyncMock()
        return mock

    @pytest.fixture
    def key_pair(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @pytest.fixture
    def second_key_pair(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @pytest.fixture
    def jwks(self, key_pair: Any) -> dict[str, Any]:
        return {"keys": [key_pair.as_dict(private=False)]}

    @pytest.fixture
    def jwks_rotated(self, key_pair: Any, second_key_pair: Any) -> dict[str, Any]:
        # Both keys present after rotation
        return {"keys": [key_pair.as_dict(private=False), second_key_pair.as_dict(private=False)]}

    def create_token(self, key: Any, claims: dict[str, Any]) -> str:
        headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
        return jwt.encode(headers, claims, key).decode("utf-8")

    @pytest.mark.asyncio
    async def test_key_rotation_with_issuer_mismatch(
        self, mock_oidc: AsyncMock, second_key_pair: Any, jwks: dict[str, Any], jwks_rotated: dict[str, Any]
    ) -> None:
        """
        Test Case 4 (Key Rotation + Mismatch):
        Simulate a scenario where validation fails signature first (triggering refresh),
        but then fails issuer check even if signature becomes valid.
        """
        # Scenario:
        # 1. Token signed with Key B (second_key_pair).
        # 2. Token has WRONG issuer.
        # 3. OIDC Provider initially only has Key A (key_pair).
        # 4. First validation fails sig (Key B unknown).
        # 5. Validator refreshes keys -> gets Key A + Key B.
        # 6. Second validation passes sig (Key B found), but MUST fail issuer check.

        expected_issuer = "https://valid.com/"
        malicious_issuer = "https://evil.com/"

        validator = TokenValidator(pii_salt=SecretStr("test-salt"), oidc_provider=mock_oidc, audience="aud", issuer=expected_issuer)

        # Setup mock behavior
        async def get_jwks_side_effect(force_refresh: bool = False) -> dict[str, Any]:
            if force_refresh:
                return jwks_rotated
            return jwks

        mock_oidc.get_jwks.side_effect = get_jwks_side_effect

        # Create token with Key B AND Wrong Issuer
        token = self.create_token(
            second_key_pair, {"sub": "u", "iss": malicious_issuer, "aud": "aud", "exp": 9999999999}
        )

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            await validator.validate_token(token)

        # Verify refresh happened
        assert mock_oidc.get_jwks.call_count == 2
        mock_oidc.get_jwks.assert_called_with(force_refresh=True)

    @pytest.mark.asyncio
    async def test_concurrent_validation_mixed_issuers(
        self, mock_oidc: AsyncMock, key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Test Case 5 (Concurrent Validation):
        Run multiple validations concurrently where some have valid issuers and some have invalid ones.
        """
        mock_oidc.get_jwks.return_value = jwks
        expected_issuer = "https://valid.com/"
        validator = TokenValidator(pii_salt=SecretStr("test-salt"), oidc_provider=mock_oidc, audience="aud", issuer=expected_issuer)

        token_valid = self.create_token(
            key_pair, {"sub": "valid_user", "iss": expected_issuer, "aud": "aud", "exp": 9999999999}
        )

        token_invalid = self.create_token(
            key_pair, {"sub": "invalid_user", "iss": "https://invalid.com/", "aud": "aud", "exp": 9999999999}
        )

        async def validate_valid() -> str:
            res = await validator.validate_token(token_valid)
            return res["sub"]  # type: ignore[no-any-return]

        async def validate_invalid() -> None:
            with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
                await validator.validate_token(token_invalid)

        # Run 50 mixed tasks
        tasks: list[Any] = []
        for i in range(50):
            if i % 2 == 0:
                tasks.append(validate_valid())
            else:
                tasks.append(validate_invalid())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Check results
        for i, res in enumerate(results):
            if i % 2 == 0:
                assert res == "valid_user"
            else:
                assert res is None  # validate_invalid returns None (it asserts internally)
