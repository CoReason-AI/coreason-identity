# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import pytest
from unittest.mock import Mock, AsyncMock, patch
from authlib.jose import JsonWebKey, jwt
from coreason_identity.validator import TokenValidator, TokenValidatorAsync
from coreason_identity.oidc_provider import OIDCProviderAsync, OIDCProvider
from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InvalidAudienceError,
    SignatureVerificationError,
    TokenExpiredError,
    InvalidTokenError
)
import time

@pytest.fixture
def key_pair():
    return JsonWebKey.generate_key("RSA", 2048, is_private=True)

@pytest.fixture
def jwks(key_pair):
    return {"keys": [key_pair.as_dict(private=False)]}

def create_token(key, claims, headers=None):
    if headers is None:
        headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
    return jwt.encode(headers, claims, key).decode("utf-8")

# --- Async Tests ---

@pytest.fixture
def async_provider():
    return AsyncMock(spec=OIDCProviderAsync)

@pytest.mark.asyncio
async def test_async_validate_success(async_provider, key_pair, jwks):
    async_provider.get_jwks.return_value = jwks

    validator = TokenValidatorAsync(async_provider, audience="aud")

    claims = {"sub": "user", "aud": "aud", "exp": int(time.time()) + 3600}
    token = create_token(key_pair, claims)

    res = await validator.validate_token(token)
    assert res["sub"] == "user"

@pytest.mark.asyncio
async def test_async_validate_expired(async_provider, key_pair, jwks):
    async_provider.get_jwks.return_value = jwks
    validator = TokenValidatorAsync(async_provider, audience="aud")

    claims = {"sub": "user", "aud": "aud", "exp": int(time.time()) - 3600}
    token = create_token(key_pair, claims)

    with pytest.raises(TokenExpiredError):
        await validator.validate_token(token)

@pytest.mark.asyncio
async def test_async_validate_invalid_aud(async_provider, key_pair, jwks):
    async_provider.get_jwks.return_value = jwks
    validator = TokenValidatorAsync(async_provider, audience="aud")

    claims = {"sub": "user", "aud": "wrong", "exp": int(time.time()) + 3600}
    token = create_token(key_pair, claims)

    with pytest.raises(InvalidAudienceError):
        await validator.validate_token(token)

@pytest.mark.asyncio
async def test_async_validate_bad_sig(async_provider, key_pair, jwks):
    async_provider.get_jwks.return_value = jwks
    validator = TokenValidatorAsync(async_provider, audience="aud")

    claims = {"sub": "user", "aud": "aud", "exp": int(time.time()) + 3600}

    # Sign with different key
    other_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    token = create_token(other_key, claims, headers={"alg": "RS256", "kid": key_pair.as_dict()["kid"]})

    with pytest.raises(SignatureVerificationError):
        await validator.validate_token(token)

@pytest.mark.asyncio
async def test_async_validate_malformed(async_provider, jwks):
    async_provider.get_jwks.return_value = jwks
    validator = TokenValidatorAsync(async_provider, audience="aud")

    with pytest.raises(CoreasonIdentityError):
        await validator.validate_token("not.a.token")

@pytest.mark.asyncio
async def test_async_validate_refresh_keys(async_provider, key_pair, jwks):
    # First call returns empty keys, second returns correct keys
    async_provider.get_jwks.side_effect = [{"keys": []}, jwks]

    validator = TokenValidatorAsync(async_provider, audience="aud")

    claims = {"sub": "user", "aud": "aud", "exp": int(time.time()) + 3600}
    token = create_token(key_pair, claims)

    res = await validator.validate_token(token)
    assert res["sub"] == "user"
    assert async_provider.get_jwks.call_count == 2
    # Check force_refresh=True on second call
    assert async_provider.get_jwks.call_args_list[1][1]["force_refresh"] is True

@pytest.mark.asyncio
async def test_async_validate_alg_none(async_provider, jwks):
    # Test for alg: none vulnerability
    # We construct a token with alg: none
    async_provider.get_jwks.return_value = jwks
    validator = TokenValidatorAsync(async_provider, audience="aud")

    claims = {"sub": "hacker", "aud": "aud", "exp": int(time.time()) + 3600}
    # authlib might block encode with none if not allowed, but let's try to bypass or use a raw construction if needed
    # Authlib encoding with alg: none
    header = {"alg": "none"}
    # Manually construct JWT to ensure it's "none"
    # Or rely on authlib encode if we pass a key that supports none? none doesn't use key.
    # JWT with alg:none usually has empty signature

    # We can use jwt.encode with alg="none" but we need to see if authlib allows it.
    # Actually, we can just use a plain string construction for this test to be sure.
    import base64
    import json

    def b64encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    token = f"{b64encode(header)}.{b64encode(claims)}."

    # Validator should reject it because we initialized JsonWebToken(["RS256"])

    with pytest.raises(InvalidTokenError): # Or SignatureVerificationError depending on how Authlib handles it
        await validator.validate_token(token)

# --- Sync Facade Tests ---

def test_sync_validate_delegation(key_pair, jwks):
    mock_async_provider = AsyncMock(spec=OIDCProviderAsync)
    mock_async_provider.get_jwks.return_value = jwks

    provider = OIDCProvider("url")
    provider._async = mock_async_provider

    validator = TokenValidator(provider, audience="aud")

    claims = {"sub": "user", "aud": "aud", "exp": int(time.time()) + 3600}
    token = create_token(key_pair, claims)

    res = validator.validate_token(token)
    assert res["sub"] == "user"
