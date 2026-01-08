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
Verification test for the exception hierarchy fix.
Ensures that validation failures raise InvalidTokenError (or subclass),
allowing the consumer to catch a single exception type.
"""

from typing import Any, Dict
from unittest.mock import patch

import pytest
from authlib.jose import JsonWebKey, jwt
from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.exceptions import InvalidTokenError
from coreason_identity.manager import IdentityManager


@pytest.fixture
def key_pair() -> Any:
    return JsonWebKey.generate_key("RSA", 2048, is_private=True)


@pytest.fixture
def jwks(key_pair: Any) -> Dict[str, Any]:
    return {"keys": [key_pair.as_dict(private=False)]}


def create_token(key: Any, claims: Dict[str, Any]) -> str:
    headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
    return jwt.encode(headers, claims, key).decode("utf-8")  # type: ignore[no-any-return]


def test_missing_claim_raises_invalid_token_error(key_pair: Any, jwks: Dict[str, Any]) -> None:
    """
    Test that a token missing a required claim (like 'exp') raises InvalidTokenError.
    """
    domain = "test.auth0.com"
    config = CoreasonIdentityConfig(domain=domain, audience="aud")

    # Mock OIDC provider to return keys
    with patch("coreason_identity.manager.OIDCProvider") as MockOIDC:
        mock_oidc_instance = MockOIDC.return_value
        mock_oidc_instance.get_jwks.return_value = jwks

        manager = IdentityManager(config)

        # Create token missing 'exp' (which is essential)
        claims = {
            "sub": "user123",
            "aud": "aud",
            "iss": f"https://{domain}/",
            # "exp": missing
        }
        token = create_token(key_pair, claims)

        # Verify that we can catch InvalidTokenError
        try:
            manager.validate_token(f"Bearer {token}")
            pytest.fail("Should have raised InvalidTokenError")
        except InvalidTokenError:
            # Success! The fix works.
            pass
        except Exception as e:
            pytest.fail(f"Raised unexpected exception type: {type(e).__name__}: {e}")


def test_mapper_validation_raises_invalid_token_error(key_pair: Any, jwks: Dict[str, Any]) -> None:
    """
    Test that a token with valid crypto but missing mapping fields (like 'email')
    raises InvalidTokenError.
    """
    domain = "test.auth0.com"
    config = CoreasonIdentityConfig(domain=domain, audience="aud")

    with patch("coreason_identity.manager.OIDCProvider") as MockOIDC:
        mock_oidc_instance = MockOIDC.return_value
        mock_oidc_instance.get_jwks.return_value = jwks

        manager = IdentityManager(config)

        # Valid crypto claims, but missing 'email' required by IdentityMapper
        import time

        claims = {
            "sub": "user123",
            "aud": "aud",
            "iss": f"https://{domain}/",
            "exp": int(time.time()) + 3600,
            # "email": missing
        }
        token = create_token(key_pair, claims)

        try:
            manager.validate_token(f"Bearer {token}")
            pytest.fail("Should have raised InvalidTokenError")
        except InvalidTokenError:
            # Success! The fix works.
            pass
        except Exception as e:
            pytest.fail(f"Raised unexpected exception type: {type(e).__name__}: {e}")
