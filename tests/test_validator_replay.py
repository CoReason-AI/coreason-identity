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
Tests for TokenValidator (Replay Protection).
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from authlib.jose import JsonWebKey, jwt
from pydantic import SecretStr

from coreason_identity.exceptions import CoreasonIdentityError, TokenReplayError
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import MemoryTokenCache, TokenValidator


@pytest.fixture
def mock_oidc_provider() -> Mock:
    provider = Mock(spec=OIDCProvider)
    provider.get_jwks = AsyncMock()
    return provider


@pytest.fixture
def key_pair() -> Any:
    return JsonWebKey.generate_key("RSA", 2048, is_private=True)


@pytest.fixture
def jwks(key_pair: Any) -> dict[str, Any]:
    return {"keys": [key_pair.as_dict(private=False)]}


@pytest.fixture
def validator(mock_oidc_provider: Mock, jwks: dict[str, Any]) -> TokenValidator:
    mock_oidc_provider.get_jwks.return_value = jwks
    return TokenValidator(
        oidc_provider=mock_oidc_provider,
        audience="my-audience",
        issuer="https://valid-issuer.com/",
        pii_salt=SecretStr("test-salt"),
        allowed_algorithms=["RS256"],
        cache=MemoryTokenCache(),  # Use Memory Cache
    )


def create_token(
    key: Any,
    claims: dict[str, Any],
    headers: dict[str, Any] | None = None,
    alg: str = "RS256",
) -> str:
    if headers is None:
        headers = {"alg": alg, "kid": key.as_dict()["kid"] if key else "none"}
    return jwt.encode(headers, claims, key).decode("utf-8")


@pytest.mark.asyncio
async def test_replay_attack_jti_cache(validator: TokenValidator, key_pair: Any) -> None:
    """Test that reusing a JTI raises TokenReplayError."""
    # Ensure cache is empty
    assert len(validator.cache._cache) == 0

    claims = {
        "sub": "user123",
        "aud": "my-audience",
        "iss": "https://valid-issuer.com/",
        "exp": 9999999999,
        "jti": "unique-jti-1",
    }
    token = create_token(key_pair, claims)

    # First validation: Success
    await validator.validate_token(token)

    # Ensure it's in cache now
    assert "unique-jti-1" in validator.cache._cache

    # Second validation (Replay): Fail
    with pytest.raises(TokenReplayError, match="Replay detected"):
        await validator.validate_token(token)


@pytest.mark.asyncio
async def test_replay_cache_concurrency(validator: TokenValidator, key_pair: Any) -> None:
    """Test concurrent validation of the SAME token (Race Condition Check)."""
    assert len(validator.cache._cache) == 0

    claims = {
        "sub": "user123",
        "aud": "my-audience",
        "iss": "https://valid-issuer.com/",
        "exp": 9999999999,
        "jti": "concurrent-jti",
    }
    token = create_token(key_pair, claims)

    # Simulate 10 concurrent requests with the SAME token
    tasks = [validator.validate_token(token) for _ in range(10)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    successes = [r for r in results if not isinstance(r, Exception)]
    failures = [r for r in results if isinstance(r, TokenReplayError)]

    # Only ONE should succeed
    assert len(successes) == 1
    assert len(failures) == 9


@pytest.mark.asyncio
async def test_missing_jti_allowed(validator: TokenValidator, key_pair: Any) -> None:
    """If JTI is missing, replay protection is skipped (or enforce policy?)."""
    # Current implementation implies JTI check only if JTI exists?
    # Actually, TokenValidator SHOULD require JTI for strict security, but let's check behavior.
    claims = {
        "sub": "user123",
        "aud": "my-audience",
        "iss": "https://valid-issuer.com/",
        "exp": 9999999999,
        # No JTI
    }
    token = create_token(key_pair, claims)

    # First validation
    await validator.validate_token(token)
    # Second validation - Should succeed if JTI is not mandatory, or fail if mandatory.
    # Assuming standard behavior: if no JTI, cannot check replay.
    await validator.validate_token(token)
    # (No assertion needed, just shouldn't raise)


@pytest.mark.asyncio
async def test_replay_cleanup(validator: TokenValidator, key_pair: Any) -> None:
    """Test that expired tokens are cleaned up from cache."""
    # This relies on MemoryTokenCache._cleanup implementation detail
    # We can manually trigger cleanup if exposed, or wait (not ideal for unit tests).
    # MemoryTokenCache typically cleans up on insertion or via periodic task.
    # Let's inspect MemoryTokenCache:
    # It has a _cleanup() method called in is_jti_used potentially?

    # Mock time for strict control?
    # Since we can't easily mock time inside the class without dependency injection,
    # we verify basic behavior: cleanup happens.

    cache = validator.cache
    assert isinstance(cache, MemoryTokenCache)

    # Insert an expired token
    # "exp" is timestamp. Let's say it expired 10 seconds ago.
    import time

    expired_jti = "expired-jti"
    future_jti = "future-jti"
    now = int(time.time())

    # Manually seed cache
    cache._cache[expired_jti] = now - 10
    cache._cache[future_jti] = now + 100

    # Trigger cleanup (it's called in is_jti_used)
    cache.is_jti_used("new-jti", now + 300)

    # Verify expired is gone, future remains
    assert expired_jti not in cache._cache
    assert future_jti in cache._cache
