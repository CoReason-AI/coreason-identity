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
Modernization edge cases.
Tests specifically targeting areas affected by strict type checking and linting modernizations.
"""

from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from authlib.jose import JsonWebKey, jwt

from coreason_identity.exceptions import CoreasonIdentityError, InvalidTokenError
from coreason_identity.identity_mapper import IdentityMapper, RawIdPClaims
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestIdentityMapperTypeBoundaries:
    """
    Test edge cases for IdentityMapper regarding strict type normalization.
    """

    def test_ensure_list_of_strings_mixed_types(self) -> None:
        """
        Verify that `ensure_list_of_strings` handles mixed lists (int, None, bool) correctly
        and converts them to strings, maintaining robustness.
        """
        # Testing RawIdPClaims directly since UserContext enforces enums and would fail
        claims = {
            "sub": "user1",
            "email": "u@e.com",
            "groups": ["valid", 123, None, True],
        }
        # 123 -> "123", True -> "True", None -> filtered out
        raw = RawIdPClaims(**claims)
        assert "valid" in raw.groups
        assert "123" in raw.groups
        assert "True" in raw.groups
        assert None not in raw.groups

    def test_ensure_list_of_strings_tuple_input(self) -> None:
        """
        Verify that a tuple input is correctly converted to a list of strings.
        This tests the `isinstance(v, (list, tuple))` logic.
        """
        # Testing RawIdPClaims directly
        claims = {
            "sub": "user1",
            "email": "u@e.com",
            "groups": ("group1", "group2"),
        }
        raw = RawIdPClaims(**claims)
        assert raw.groups == ["group1", "group2"]

    def test_ensure_list_of_strings_single_string_in_list(self) -> None:
        """
        Verify that a single string inside a list remains a list of one string.
        """
        # Testing RawIdPClaims directly
        claims = {
            "sub": "user1",
            "email": "u@e.com",
            "groups": ["group1"],
        }
        raw = RawIdPClaims(**claims)
        assert raw.groups == ["group1"]

    def test_raw_claims_model_direct_instantiation(self) -> None:
        """
        Test direct instantiation of RawIdPClaims with weird inputs to verify Pydantic validators.
        """
        # Case: 'scope' (standard claim) as single string (should split and map to scopes)
        # Note: We must pass it as a dict to bypass the strict signature of __init__ if using aliases
        # or just pass valid fields. RawIdPClaims accepts **data.
        raw = RawIdPClaims(sub="s", email="e@e.com", scope="scope1 scope2")
        assert raw.scopes == ["scope1", "scope2"]

        # Case: scopes as explicit list
        raw2 = RawIdPClaims(sub="s", email="e@e.com", scopes=["s1", "s2"])
        assert raw2.scopes == ["s1", "s2"]

        # Case: scopes as tuple
        raw3 = RawIdPClaims(sub="s", email="e@e.com", scopes=("s1", "s2"))
        assert raw3.scopes == ["s1", "s2"]


class TestTokenValidatorTypeStress:
    """
    Test TokenValidator with inputs that stress type checking assumptions (though checked at runtime).
    """

    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        provider = Mock(spec=OIDCProvider)
        provider.get_jwks = AsyncMock()
        return provider

    @pytest.fixture
    def key_pair(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @pytest.fixture
    def jwks(self, key_pair: Any) -> dict[str, Any]:
        return {"keys": [key_pair.as_dict(private=False)]}

    @pytest.fixture
    def validator(self, mock_oidc_provider: Mock, jwks: dict[str, Any]) -> TokenValidator:
        mock_oidc_provider.get_jwks.return_value = jwks
        return TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="aud",
            issuer="https://iss/",
        )

    def create_token(self, key: Any, claims: dict[str, Any]) -> str:
        headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
        return jwt.encode(headers, claims, key).decode("utf-8")

    @pytest.mark.asyncio
    async def test_validate_token_with_boolean_audience(self, validator: TokenValidator, key_pair: Any) -> None:
        """
        Test token with boolean 'aud' claim.
        Authlib might convert or fail validation. We expect failure (aud mismatch).
        """
        claims = {
            "sub": "user",
            "aud": True,  # Invalid type for aud
            "iss": "https://iss/",
            "exp": 9999999999,
        }
        token = self.create_token(key_pair, claims)

        # Should raise invalid claim or audience error
        with pytest.raises(CoreasonIdentityError):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_validate_token_with_numeric_string_audience(self, validator: TokenValidator, key_pair: Any) -> None:
        """
        Test token with 'aud' as numeric string "123".
        If expected aud is "aud", this should fail.
        """
        claims = {
            "sub": "user",
            "aud": "123",
            "iss": "https://iss/",
            "exp": 9999999999,
        }
        token = self.create_token(key_pair, claims)

        with pytest.raises(InvalidTokenError):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_validate_token_with_none_payload_value(self, validator: TokenValidator, key_pair: Any) -> None:
        """
        Test token where a standard claim is explicitly None (if encoded).
        """
        claims = {
            "sub": "user",
            "aud": "aud",
            "iss": "https://iss/",
            "exp": 9999999999,
            "custom": None,  # Custom claim is None
        }
        token = self.create_token(key_pair, claims)

        # Should pass validation, custom claim should be None in output
        result = await validator.validate_token(token)
        assert result["custom"] is None
