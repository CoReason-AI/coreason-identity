
import time
from typing import Any, Dict
from unittest.mock import AsyncMock, Mock

import pytest
from authlib.jose import JsonWebKey, jwt
from coreason_identity.exceptions import CoreasonIdentityError, SignatureVerificationError
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestDoS:
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
    def jwks(self, key_pair: Any) -> Dict[str, Any]:
        return {"keys": [key_pair.as_dict(private=False)]}

    @pytest.fixture
    def validator(self, mock_oidc_provider: Mock) -> TokenValidator:
        return TokenValidator(oidc_provider=mock_oidc_provider, audience="my-audience")

    @pytest.mark.asyncio
    async def test_dos_bad_signature_known_kid_no_refresh(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        """
        Verify that a bad signature with a KNOWN kid does NOT trigger a JWKS refresh.
        This prevents DoS attacks.
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "attacker",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now + 3600,
        }

        # Sign with a different key
        attacker_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        # Use KID of expected key but sign with attacker key (Bad Signature)
        headers = {"alg": "RS256", "kid": key_pair.as_dict()["kid"]}
        token = jwt.encode(headers, claims, attacker_key)
        token_str = token.decode("utf-8")

        # This should raise SignatureVerificationError
        with pytest.raises(SignatureVerificationError):
            await validator.validate_token(token_str)

        # Verify calls to get_jwks
        calls = mock_oidc_provider.get_jwks.await_args_list

        # Check that NO call has force_refresh=True
        assert not any(
            call.kwargs.get("force_refresh") is True for call in calls
        ), "get_jwks called with force_refresh=True, allowing DoS!"

    @pytest.mark.asyncio
    async def test_key_rotation_refresh(
        self, validator: TokenValidator, mock_oidc_provider: Mock, key_pair: Any, jwks: Dict[str, Any]
    ) -> None:
        """
        Verify that an UNKNOWN kid DOES trigger a JWKS refresh (legitimate key rotation case).
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        now = int(time.time())
        claims = {
            "sub": "user",
            "aud": "my-audience",
            "iss": "https://valid-issuer.com",
            "exp": now + 3600,
        }

        # Sign with a NEW key (simulating rotated key)
        new_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        new_kid = "new-key-id"

        headers = {"alg": "RS256", "kid": new_kid}
        token = jwt.encode(headers, claims, new_key)
        token_str = token.decode("utf-8")

        with pytest.raises(SignatureVerificationError):
            await validator.validate_token(token_str)

        # But get_jwks MUST be called with force_refresh=True because kid was unknown
        calls = mock_oidc_provider.get_jwks.await_args_list
        assert any(
            call.kwargs.get("force_refresh") is True for call in calls
        ), "get_jwks SHOULD be called with force_refresh=True for unknown key!"

    @pytest.mark.asyncio
    async def test_dos_malformed_token_no_refresh(
        self, validator: TokenValidator, mock_oidc_provider: Mock, jwks: Dict[str, Any]
    ) -> None:
        """
        Verify that a MALFORMED token (garbage) does NOT trigger a JWKS refresh.
        Case 1: 3 parts but invalid base64 (extract_header fails).
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        token_str = "this.is.garbage"

        # This should raise CoreasonIdentityError or InvalidTokenError
        with pytest.raises(CoreasonIdentityError):
            await validator.validate_token(token_str)

        # Verify calls to get_jwks
        calls = mock_oidc_provider.get_jwks.await_args_list

        # Check that NO call has force_refresh=True
        assert not any(
            call.kwargs.get("force_refresh") is True for call in calls
        ), "get_jwks called with force_refresh=True for malformed token!"

    @pytest.mark.asyncio
    async def test_dos_really_malformed_token_no_refresh(
        self, validator: TokenValidator, mock_oidc_provider: Mock, jwks: Dict[str, Any]
    ) -> None:
        """
        Verify that a REALLY MALFORMED token (0 or 1 part) does NOT trigger a JWKS refresh.
        Case 2: Not enough parts (covers 'else' block).
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        token_str = "garbage_without_dots"

        with pytest.raises(CoreasonIdentityError):
            await validator.validate_token(token_str)

        calls = mock_oidc_provider.get_jwks.await_args_list
        assert not any(
            call.kwargs.get("force_refresh") is True for call in calls
        ), "get_jwks called with force_refresh=True for really malformed token!"
