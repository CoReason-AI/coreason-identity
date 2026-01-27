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
Edge case tests for IdentityManager issuer validation.
"""

import time
from typing import Any, Dict
from unittest.mock import AsyncMock, patch

import pytest
from authlib.jose import JsonWebKey, jwt

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.manager import IdentityManager


@pytest.fixture
def key_pair() -> Any:
    return JsonWebKey.generate_key("RSA", 2048, is_private=True)


@pytest.fixture
def jwks(key_pair: Any) -> Dict[str, Any]:
    return {"keys": [key_pair.as_dict(private=False)]}


def create_token(key: Any, claims: Dict[str, Any], headers: Dict[str, Any] | None = None) -> bytes:
    if headers is None:
        headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
    return jwt.encode(headers, claims, key)  # type: ignore[no-any-return]


def test_init_with_trailing_slash_in_domain() -> None:
    """
    Test that if config.domain has a trailing slash, the constructed issuer
    normalizes it to a single slash.
    """
    domain = "test.auth0.com/"
    config = CoreasonIdentityConfig(domain=domain, audience="aud")

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
    ):
        IdentityManager(config)

        expected_issuer = "https://test.auth0.com/"
        MockValidator.assert_called_once()
        args, kwargs = MockValidator.call_args
        assert kwargs["issuer"] == expected_issuer


def test_init_with_protocol_in_domain() -> None:
    """
    Test behavior when domain includes protocol.
    It should be stripped and forced to https.
    """
    domain = "https://test.auth0.com"
    config = CoreasonIdentityConfig(domain=domain, audience="aud")

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
    ):
        IdentityManager(config)

        expected_issuer = "https://test.auth0.com/"
        MockValidator.assert_called_once()
        args, kwargs = MockValidator.call_args
        assert kwargs["issuer"] == expected_issuer


def test_validate_token_missing_iss_claim(key_pair: Any, jwks: Dict[str, Any]) -> None:
    """Test validation when 'iss' claim is missing from token."""
    domain = "test.auth0.com"
    audience = "test-audience"
    config = CoreasonIdentityConfig(domain=domain, audience=audience)

    # We mock OIDCProvider to be injected into IdentityManager
    # But IdentityManager instantiates it internally.
    # We patch the class.
    with patch("coreason_identity.manager.OIDCProvider") as MockOIDC:
        mock_oidc_instance = MockOIDC.return_value
        # get_jwks is async
        mock_oidc_instance.get_jwks = AsyncMock(return_value=jwks)

        manager = IdentityManager(config)

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": audience,
            # Missing iss
            "exp": now + 3600,
            "email": "test@example.com",
        }
        token = create_token(key_pair, claims).decode("utf-8")

        # Should fail because iss is marked essential=True in TokenValidator
        with pytest.raises(CoreasonIdentityError, match="Missing claim"):
            manager.validate_token(f"Bearer {token}")


def test_validate_token_no_trailing_slash_match(key_pair: Any, jwks: Dict[str, Any]) -> None:
    """
    Test validation when token issuer is valid domain but missing trailing slash.
    Config expects: https://domain/
    Token has: https://domain
    Should fail due to strict string matching.
    """
    domain = "test.auth0.com"
    audience = "test-audience"
    config = CoreasonIdentityConfig(domain=domain, audience=audience)

    with patch("coreason_identity.manager.OIDCProvider") as MockOIDC:
        mock_oidc_instance = MockOIDC.return_value
        mock_oidc_instance.get_jwks = AsyncMock(return_value=jwks)

        manager = IdentityManager(config)

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": audience,
            "iss": f"https://{domain}",  # No trailing slash
            "exp": now + 3600,
            "email": "test@example.com",
        }
        token = create_token(key_pair, claims).decode("utf-8")

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            manager.validate_token(f"Bearer {token}")


def test_validate_token_http_protocol(key_pair: Any, jwks: Dict[str, Any]) -> None:
    """Test token with http:// protocol vs https:// config."""
    domain = "test.auth0.com"
    audience = "test-audience"
    config = CoreasonIdentityConfig(domain=domain, audience=audience)

    with patch("coreason_identity.manager.OIDCProvider") as MockOIDC:
        mock_oidc_instance = MockOIDC.return_value
        mock_oidc_instance.get_jwks = AsyncMock(return_value=jwks)

        manager = IdentityManager(config)

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": audience,
            "iss": f"http://{domain}/",  # HTTP
            "exp": now + 3600,
            "email": "test@example.com",
        }
        token = create_token(key_pair, claims).decode("utf-8")

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            manager.validate_token(f"Bearer {token}")


def test_init_with_http_protocol_in_domain() -> None:
    """
    Test behavior when domain includes http:// protocol.
    It should be stripped and forced to https.
    """
    domain = "http://test.auth0.com"
    config = CoreasonIdentityConfig(domain=domain, audience="aud")

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
    ):
        IdentityManager(config)

        expected_issuer = "https://test.auth0.com/"
        MockValidator.assert_called_once()
        args, kwargs = MockValidator.call_args
        assert kwargs["issuer"] == expected_issuer
