# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import time
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from authlib.jose import JsonWebKey, jwt

from coreason_identity.exceptions import InvalidTokenError
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestValidatorSecurityComplex:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        provider = Mock(spec=OIDCProvider)
        provider.get_jwks = AsyncMock()
        provider.get_issuer = AsyncMock(return_value="https://valid-issuer.com")
        return provider

    @pytest.fixture
    def rsa_key_pair(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True)

    @pytest.fixture
    def ec_key_pair(self) -> Any:
        return JsonWebKey.generate_key("EC", "P-256", is_private=True)

    @pytest.fixture
    def jwks(self, rsa_key_pair: Any, ec_key_pair: Any) -> dict[str, Any]:
        return {"keys": [rsa_key_pair.as_dict(private=False), ec_key_pair.as_dict(private=False)]}

    def create_token(
        self, key: Any, claims: dict[str, Any], headers: dict[str, Any] | None = None, alg: str = "RS256"
    ) -> str:
        if headers is None:
            headers = {"alg": alg, "kid": key.as_dict().get("kid")}
        token_bytes = jwt.encode(headers, claims, key)
        return token_bytes.decode("utf-8")

    @pytest.mark.asyncio
    async def test_mixed_algorithm_support(
        self, mock_oidc_provider: Mock, rsa_key_pair: Any, ec_key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Verify that multiple allowed algorithms can be configured and used simultaneously.
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        # Allow both RS256 and ES256
        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="aud",
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256", "ES256"],
        )

        claims = {
            "sub": "user123",
            "aud": "aud",
            "iss": "https://valid-issuer.com",
            "exp": int(time.time()) + 3600,
        }

        # 1. Validate RS256 token
        token_rsa = self.create_token(rsa_key_pair, claims, alg="RS256")
        res_rsa = await validator.validate_token(token_rsa)
        assert res_rsa["sub"] == "user123"

        # 2. Validate ES256 token
        token_ec = self.create_token(ec_key_pair, claims, alg="ES256")
        res_ec = await validator.validate_token(token_ec)
        assert res_ec["sub"] == "user123"

    @pytest.mark.asyncio
    async def test_mixed_algorithm_rejection(
        self, mock_oidc_provider: Mock, rsa_key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Verify that if only one algorithm is allowed, others (even validly signed) are rejected.
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        # Only allow ES256
        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="aud",
            issuer="https://valid-issuer.com",
            allowed_algorithms=["ES256"],
        )

        claims = {
            "sub": "user123",
            "aud": "aud",
            "iss": "https://valid-issuer.com",
            "exp": int(time.time()) + 3600,
        }

        # Token is valid RS256 signed with correct key, but config forbids RS256
        token_rsa = self.create_token(rsa_key_pair, claims, alg="RS256")

        with pytest.raises(InvalidTokenError):
            await validator.validate_token(token_rsa)

    @pytest.mark.asyncio
    async def test_none_algorithm_attack(self, mock_oidc_provider: Mock, jwks: dict[str, Any]) -> None:
        """
        Verify that 'none' algorithm is strictly rejected even if somehow bypassed/injected.
        Also verify explicit configuration cannot accidentally allow it easily (unless explicitly added).
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        # Standard config
        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="aud",
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256"],
        )

        claims = {"sub": "hacker", "aud": "aud", "iss": "https://valid-issuer.com", "exp": int(time.time()) + 3600}

        # Create 'none' alg token manually
        # Authlib jwt.encode refuses 'none' unless allowed, so we might need to force it or construct raw string
        header = '{"alg":"none","typ":"JWT"}'
        import base64
        import json

        def b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).replace(b"=", b"").decode("utf-8")

        h = b64url(header.encode())
        p = b64url(json.dumps(claims).encode())
        token_none = f"{h}.{p}."

        # Should fail
        with pytest.raises(InvalidTokenError):
            await validator.validate_token(token_none)

    @pytest.mark.asyncio
    async def test_key_confusion_public_key_as_secret(
        self, mock_oidc_provider: Mock, rsa_key_pair: Any, jwks: dict[str, Any]
    ) -> None:
        """
        Simulate Key Confusion Attack:
        The attacker signs a token using HS256, but uses the server's Public Key (PEM format) as the HMAC secret.
        If the server accepts HS256 and finds a key with matching KID (the RSA public key),
        and naïvely uses that key material for HMAC verification, the attack succeeds.

        Strict whitelisting prevents this because HS256 is not allowed.
        """
        mock_oidc_provider.get_jwks.return_value = jwks

        # Validator expects RS256 only
        validator = TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="aud",
            issuer="https://valid-issuer.com",
            allowed_algorithms=["RS256"],
        )

        claims = {"sub": "hacker", "aud": "aud", "iss": "https://valid-issuer.com", "exp": int(time.time()) + 3600}

        # Attacker constructs token signed with HS256 using the RSA Public Key as the secret
        # 1. Extract public JWK
        pub_jwk = rsa_key_pair.as_dict(private=False)
        # 2. Import as Key object (Authlib needs this step to export PEM)
        pub_key_obj = JsonWebKey.import_key(pub_jwk, {"kty": "RSA"})
        # 3. Export as PEM (this is what attackers use as the HMAC secret)
        pub_key_pem = pub_key_obj.as_pem()  # type: ignore[attr-defined]

        # Create a new OctKey using the PEM content as the secret
        # Note: In real attacks, they use the PEM string bytes as the secret
        # Authlib's import_key protects against this, so we manually construct the key dict
        import base64

        # Remove headers/footers for raw key material usage if we were using raw bytes,
        # but here we treat the WHOLE PEM string as the secret bytes.
        k_bytes = pub_key_pem
        k_b64 = base64.urlsafe_b64encode(k_bytes).replace(b"=", b"").decode("utf-8")

        attacker_key_dict = {"kty": "oct", "k": k_b64, "kid": rsa_key_pair.as_dict()["kid"]}

        # Sign it using the attacker key
        # We need to pass the dict directly or import it as OctKey (which is allowed if it's a dict)
        attacker_key = JsonWebKey.import_key(attacker_key_dict)

        token_confused = self.create_token(
            attacker_key,
            claims,
            headers={"alg": "HS256", "kid": attacker_key_dict["kid"]},
            alg="HS256",
        )

        # Validation should fail immediately due to algorithm mismatch
        with pytest.raises(InvalidTokenError):
            await validator.validate_token(token_confused)
