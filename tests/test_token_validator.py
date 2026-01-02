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
from typing import Any, Dict
from unittest.mock import Mock, patch

import pytest
from authlib.jose import jwt, JoseError
from authlib.jose import JsonWebKey

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InvalidAudienceError,
    SignatureVerificationError,
    TokenExpiredError,
)
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.token_validator import TokenValidator


@pytest.fixture  # type: ignore[misc]
def mock_config() -> CoreasonIdentityConfig:
    return CoreasonIdentityConfig(domain="auth.coreason.com", audience="api://coreason")  # type: ignore[call-arg]


@pytest.fixture  # type: ignore[misc]
def rsa_key() -> Any:
    return JsonWebKey.generate_key(kty="RSA", crv_or_size=2048, is_private=True)


@pytest.fixture  # type: ignore[misc]
def mock_oidc_provider(rsa_key: Any) -> Mock:
    provider = Mock(spec=OIDCProvider)
    # Convert RSAKey to JWK dict
    jwk = rsa_key.as_dict(add_kid=True)
    jwk["kid"] = "test-key-id"
    provider.get_jwks.return_value = {"keys": [jwk]}
    return provider


@pytest.fixture  # type: ignore[misc]
def token_validator(mock_config: CoreasonIdentityConfig, mock_oidc_provider: Mock) -> TokenValidator:
    return TokenValidator(mock_config, mock_oidc_provider)


def create_token(
    payload: Dict[str, Any],
    key: Any,
    headers: Dict[str, Any] = None
) -> str:
    if headers is None:
        headers = {"kid": "test-key-id"}
    headers.setdefault("alg", "RS256")
    return jwt.encode(headers, payload, key).decode("utf-8")  # type: ignore[no-any-return]


def test_validate_token_success(
    token_validator: TokenValidator, rsa_key: Any
) -> None:
    now = int(time.time())
    payload = {
        "iss": "https://auth.coreason.com/",
        "aud": "api://coreason",
        "exp": now + 3600,
        "sub": "user123",
    }
    token = create_token(payload, rsa_key)

    claims = token_validator.validate_token(token)

    assert claims["sub"] == "user123"
    assert claims["iss"] == "https://auth.coreason.com/"


def test_validate_token_expired(
    token_validator: TokenValidator, rsa_key: Any
) -> None:
    now = int(time.time())
    payload = {
        "iss": "https://auth.coreason.com/",
        "aud": "api://coreason",
        "exp": now - 3600,  # Expired
        "sub": "user123",
    }
    token = create_token(payload, rsa_key)

    with pytest.raises(TokenExpiredError):
        token_validator.validate_token(token)


def test_validate_token_invalid_audience(
    token_validator: TokenValidator, rsa_key: Any
) -> None:
    now = int(time.time())
    payload = {
        "iss": "https://auth.coreason.com/",
        "aud": "wrong-audience",
        "exp": now + 3600,
        "sub": "user123",
    }
    token = create_token(payload, rsa_key)

    with pytest.raises(InvalidAudienceError):
        token_validator.validate_token(token)


def test_validate_token_invalid_issuer(
    token_validator: TokenValidator, rsa_key: Any
) -> None:
    now = int(time.time())
    payload = {
        "iss": "https://wrong-issuer.com/",
        "aud": "api://coreason",
        "exp": now + 3600,
        "sub": "user123",
    }
    token = create_token(payload, rsa_key)

    # Authlib treats invalid issuer as InvalidClaimError which we map to CoreasonIdentityError
    # Wait, does Authlib throw InvalidClaimError for issuer? Yes.
    # In my code: except JoseError -> CoreasonIdentityError.
    # Actually InvalidAudienceError is a subclass of InvalidClaimError.
    # InvalidIssuerError doesn't exist in Authlib, it uses InvalidClaimError with "iss".

    with pytest.raises(CoreasonIdentityError) as exc_info:
        token_validator.validate_token(token)
    assert "Invalid claim" in str(exc_info.value)


def test_validate_token_bad_signature(
    token_validator: TokenValidator
) -> None:
    # Use a different key to sign
    wrong_key = JsonWebKey.generate_key(kty="RSA", crv_or_size=2048, is_private=True)
    now = int(time.time())
    payload = {
        "iss": "https://auth.coreason.com/",
        "aud": "api://coreason",
        "exp": now + 3600,
        "sub": "user123",
    }
    # We still use the kid expected by the validator, but the signature will be wrong because key differs
    token = create_token(payload, wrong_key, headers={"kid": "test-key-id"})

    with pytest.raises(SignatureVerificationError):
        token_validator.validate_token(token)


def test_validate_token_malformed(
    token_validator: TokenValidator
) -> None:
    token = "not.a.jwt"

    with pytest.raises(CoreasonIdentityError) as exc_info:
        token_validator.validate_token(token)
    assert "Token validation failed" in str(exc_info.value) or "Unexpected error" in str(exc_info.value)


def test_validate_token_missing_claims(
    token_validator: TokenValidator, rsa_key: Any
) -> None:
    # Missing exp
    payload = {
        "iss": "https://auth.coreason.com/",
        "aud": "api://coreason",
        "sub": "user123",
    }
    token = create_token(payload, rsa_key)

    with pytest.raises(CoreasonIdentityError) as exc_info:
        token_validator.validate_token(token)
    assert "Token validation failed" in str(exc_info.value) # Likely "Missing claim: exp"


def test_validate_token_generic_jose_error(
    token_validator: TokenValidator
) -> None:
    # Patch the decode method on the jwt instance that Authlib exports
    with patch("authlib.jose.jwt.decode", side_effect=JoseError("Generic error")):
        with pytest.raises(CoreasonIdentityError) as exc_info:
            token_validator.validate_token("some.token")
        assert "Token validation failed" in str(exc_info.value)


def test_validate_token_unexpected_error(
    token_validator: TokenValidator
) -> None:
    with patch("authlib.jose.jwt.decode", side_effect=ValueError("Boom")):
        with pytest.raises(CoreasonIdentityError) as exc_info:
            token_validator.validate_token("some.token")
        assert "Unexpected error" in str(exc_info.value)
