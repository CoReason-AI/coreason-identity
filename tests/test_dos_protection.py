
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


@pytest.mark.asyncio
async def test_dos_jwks_refresh_debounce() -> None:
    """
    Simulates a DoS attack and verifies that debounce logic prevents multiple fetches.
    Starts with a cold/expired cache to ensure the first request triggers a fetch,
    and concurrent requests are debounced.
    """
    mock_client = AsyncMock()

    # Mock behavior
    # We delay the first response slightly to simulate network latency, exposing race conditions if lock missing.
    async def side_effect(url: str) -> MagicMock:
        if "openid-configuration" in url:
            return MagicMock(
                status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}
            )
        await asyncio.sleep(0.1)  # Simulate latency
        return MagicMock(status_code=200, json=lambda: {"keys": [{"kid": "old-key", "kty": "RSA"}]})

    mock_client.get.side_effect = side_effect

    # Set a large debounce interval
    provider = OIDCProvider(
        "https://idp/.well-known/openid-configuration", mock_client, min_refresh_interval=100.0
    )

    validator = TokenValidator(provider, audience="aud")

    # Setup: "loaded but just updated" to test concurrency of forced refresh
    # We must populate BOTH caches to avoid get_issuer failing
    provider._jwks_cache = {"keys": [{"kid": "old", "kty": "RSA"}]}
    provider._oidc_config_cache = {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}
    provider._last_update = time.time() - 200.0  # Older than debounce (100), but valid for cache TTL (3600)

    token_unknown_kid = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVua25vd24ifQ."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    async def attack_unknown() -> None:
        try:
            await validator.validate_token(token_unknown_kid)
        except Exception:
            pass

    # Run 5 concurrent attacks
    # They will all hit get_jwks(force_refresh=True) because unknown kid.
    # The first one should win the lock and fetch.
    # The others should wait and then see the updated cache/time and return.
    await asyncio.gather(*[attack_unknown() for _ in range(5)])

    final_call_count = mock_client.get.call_count

    # Expected: 2 calls (1 config + 1 jwks) from the SINGLE successful forced refresh.
    # If Thundering herd: 2 * 5 = 10 calls.
    print(f"Calls made: {final_call_count}")
    assert final_call_count == 2, f"Expected 2 calls (1 refresh), got {final_call_count}. Thundering herd?"


@pytest.mark.asyncio
async def test_refresh_allowed_after_interval() -> None:
    """
    Verifies that refresh is allowed after the interval passes.
    """
    mock_client = AsyncMock()

    def side_effect(url: str) -> MagicMock:
        if "openid-configuration" in url:
            return MagicMock(
                status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}
            )
        return MagicMock(status_code=200, json=lambda: {"keys": [{"kid": "old-key", "kty": "RSA"}]})

    mock_client.get.side_effect = side_effect

    provider = OIDCProvider(
        "https://idp/.well-known/openid-configuration",
        mock_client,
        min_refresh_interval=1.0,  # Short interval
    )

    validator = TokenValidator(provider, audience="aud")

    # Initial load
    await provider.get_jwks()
    initial_call_count = mock_client.get.call_count

    # Manually modify last_update to be in the past
    provider._last_update = time.time() - 2.0

    # Token with unknown kid triggers refresh request
    token_unknown_kid = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVua25vd24ifQ."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    try:
        await validator.validate_token(token_unknown_kid)
    except Exception:
        pass

    final_call_count = mock_client.get.call_count
    calls_made = final_call_count - initial_call_count

    assert calls_made == 2, "Should refresh (config + jwks) after interval passed"


@pytest.mark.asyncio
async def test_smart_refresh_known_kid() -> None:
    """
    Verifies that a token with a KNOWN kid but BAD signature does NOT trigger refresh.
    """
    mock_client = AsyncMock()
    keys = [{"kid": "known-key", "kty": "RSA", "n": "...", "e": "AQAB"}]

    def side_effect(url: str) -> MagicMock:
        if "openid-configuration" in url:
            return MagicMock(
                status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}
            )
        return MagicMock(status_code=200, json=lambda: {"keys": keys})

    mock_client.get.side_effect = side_effect

    # Disable debounce (interval=0) to ensure logic relies on validator check, not debounce
    provider = OIDCProvider(
        "https://idp/.well-known/openid-configuration", mock_client, min_refresh_interval=0.0
    )

    validator = TokenValidator(provider, audience="aud")

    # Pre-load cache
    await provider.get_jwks()
    initial_call_count = mock_client.get.call_count

    # Token with known kid but bad signature
    token_known_bad_sig = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imtub3duLWtleSJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.bad_signature"
    )

    try:
        await validator.validate_token(token_known_bad_sig)
    except Exception:
        pass

    final_call_count = mock_client.get.call_count
    calls_made = final_call_count - initial_call_count

    assert calls_made == 0, "Should NOT refresh for known kid with bad signature"


@pytest.mark.asyncio
async def test_smart_refresh_missing_kid() -> None:
    """
    Verifies that a token WITHOUT a kid triggers refresh (because we can't be sure).
    """
    mock_client = AsyncMock()

    def side_effect(url: str) -> MagicMock:
        if "openid-configuration" in url:
            return MagicMock(
                status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks", "issuer": "https://idp"}
            )
        return MagicMock(status_code=200, json=lambda: {"keys": [{"kid": "old-key", "kty": "RSA"}]})

    mock_client.get.side_effect = side_effect

    provider = OIDCProvider(
        "https://idp/.well-known/openid-configuration",
        mock_client,
        min_refresh_interval=0.0,  # Disable debounce
    )

    validator = TokenValidator(provider, audience="aud")

    # Pre-load cache
    await provider.get_jwks()
    initial_call_count = mock_client.get.call_count

    # Token with missing kid
    # Header: {"alg":"RS256","typ":"JWT"} -> eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
    token_missing_kid = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.sig"

    try:
        await validator.validate_token(token_missing_kid)
    except Exception:
        pass

    final_call_count = mock_client.get.call_count
    calls_made = final_call_count - initial_call_count

    assert calls_made == 2, "Should refresh if kid is missing"
