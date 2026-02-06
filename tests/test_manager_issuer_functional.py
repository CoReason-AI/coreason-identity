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
Functional test for IdentityManager issuer validation.
This test ensures that IdentityManager correctly configures TokenValidator to enforce issuer checks.
"""

import time
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from authlib.jose import JsonWebKey, jwt

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.manager import IdentityManager


@pytest.fixture
def key_pair() -> Any:
    # Generate a key pair for testing
    return JsonWebKey.generate_key("RSA", 2048, is_private=True)


@pytest.fixture
def jwks(key_pair: Any) -> dict[str, Any]:
    # Return public key in JWKS format
    return {"keys": [key_pair.as_dict(private=False)]}


def create_token(key: Any, claims: dict[str, Any], headers: dict[str, Any] | None = None) -> bytes:
    if headers is None:
        headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
    return jwt.encode(headers, claims, key)


def test_manager_enforces_strict_issuer(key_pair: Any, jwks: dict[str, Any]) -> None:
    """
    Verify that IdentityManager, when initialized, actually enforces issuer validation
    by performing a real validation (no mock TokenValidator).
    """
    domain = "test.auth0.com"
    audience = "test-audience"
    correct_issuer = f"https://{domain}/"
    wrong_issuer = "https://wrong-issuer.com/"

    config = CoreasonIdentityConfig(domain=domain, audience=audience, client_id="client")

    # We mock OIDCProvider to return our test keys, but we let TokenValidator run real logic
    with patch("coreason_identity.manager.OIDCProvider") as MockOIDC:
        mock_oidc_instance = MockOIDC.return_value
        mock_oidc_instance.get_jwks = AsyncMock(return_value=jwks)
        mock_oidc_instance.get_issuer = AsyncMock(return_value=correct_issuer)

        # We deliberately DO NOT mock TokenValidator or IdentityMapper here to test integration
        # However, IdentityMapper might fail if we don't return expected claims structure.
        # But validation happens before mapping.

        # NOTE: IdentityManager creates TokenValidator internally.
        # We also need to mock IdentityMapper if we want the call to succeed fully,
        # but here we expect it to fail at validation stage.

        manager = IdentityManager(config)

        # 1. Test with WRONG issuer
        now = int(time.time())
        claims_wrong = {
            "sub": "user123",
            "aud": audience,
            "iss": wrong_issuer,
            "exp": now + 3600,
            "email": "test@example.com",
        }
        token_wrong = create_token(key_pair, claims_wrong).decode("utf-8")

        # Expect failure (InvalidTokenError -> CoreasonIdentityError or specifically InvalidClaimError wrapped)
        # TokenValidator raises InvalidAudienceError or CoreasonIdentityError for invalid claims.
        # IdentityManager wraps validation in its own logic? No, validate_token calls validator.validate_token directly.

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            manager.validate_token(f"Bearer {token_wrong}")

        # 2. Test with CORRECT issuer
        claims_correct = {
            "sub": "user123",
            "aud": audience,
            "iss": correct_issuer,
            "exp": now + 3600,
            "email": "test@example.com",
        }
        token_correct = create_token(key_pair, claims_correct).decode("utf-8")

        # Should pass validation. IdentityMapper will then be called.
        # Since we didn't mock IdentityMapper, it will try to map.
        # The claims have 'sub' and 'email', so it should succeed.
        user_context = manager.validate_token(f"Bearer {token_correct}")

        assert user_context.user_id == "user123"
        assert user_context.email == "test@example.com"
