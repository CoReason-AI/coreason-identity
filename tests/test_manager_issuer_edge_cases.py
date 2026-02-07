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
Edge case tests for IdentityManagerSync issuer validation.
"""

import time
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from authlib.jose import JsonWebKey, jwt

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.manager import IdentityManagerSync


@pytest.fixture
def key_pair() -> Any:
    return JsonWebKey.generate_key("RSA", 2048, is_private=True)


@pytest.fixture
def jwks(key_pair: Any) -> dict[str, Any]:
    return {"keys": [key_pair.as_dict(private=False)]}


def create_token(key: Any, claims: dict[str, Any], headers: dict[str, Any] | None = None) -> bytes:
    if headers is None:
        headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
    return jwt.encode(headers, claims, key)


def test_init_with_trailing_slash_in_domain() -> None:
    """
    Test that if config.domain has a trailing slash, it is normalized,
    and TokenValidator is initialized with derived issuer.
    """
    domain = "test.auth0.com/"
    config = CoreasonIdentityConfig(domain=domain, audience="aud")

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
    ):
        IdentityManagerSync(config)

        MockValidator.assert_called_once()
        _, kwargs = MockValidator.call_args
        # Domain is normalized to "test.auth0.com", issuer defaults to "https://test.auth0.com/"
        assert kwargs["issuer"] == "https://test.auth0.com/"


def test_init_with_protocol_in_domain() -> None:
    """
    Test behavior when domain includes protocol.
    TokenValidator should receive derived issuer.
    """
    domain = "https://test.auth0.com"
    config = CoreasonIdentityConfig(domain=domain, audience="aud")

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
    ):
        IdentityManagerSync(config)

        MockValidator.assert_called_once()
        _, kwargs = MockValidator.call_args
        assert kwargs["issuer"] == "https://test.auth0.com/"


def test_validate_token_missing_iss_claim(key_pair: Any, jwks: dict[str, Any]) -> None:
    """Test validation when 'iss' claim is missing from token."""
    domain = "test.auth0.com"
    audience = "test-audience"
    config = CoreasonIdentityConfig(domain=domain, audience=audience)

    with patch("coreason_identity.manager.OIDCProvider") as MockOIDC:
        mock_oidc_instance = MockOIDC.return_value
        mock_oidc_instance.get_jwks = AsyncMock(return_value=jwks)
        # Mock get_issuer to return a valid issuer
        mock_oidc_instance.get_issuer = AsyncMock(return_value=f"https://{domain}/")

        manager = IdentityManagerSync(config)

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": audience,
            # Missing iss
            "exp": now + 3600,
            "email": "test@example.com",
        }
        token = create_token(key_pair, claims).decode("utf-8")

        # Should fail because iss is marked essential=True in TokenValidator (derived from get_issuer)
        with pytest.raises(CoreasonIdentityError, match="Missing claim"):
            manager.validate_token(f"Bearer {token}")


def test_validate_token_no_trailing_slash_match(key_pair: Any, jwks: dict[str, Any]) -> None:
    """
    Test validation when token issuer is valid domain but missing trailing slash.
    We must explicitly configure issuer in config to match.
    """
    domain = "test.auth0.com"
    audience = "test-audience"
    # Explicitly configure issuer without trailing slash
    oidc_issuer = f"https://{domain}"
    config = CoreasonIdentityConfig(domain=domain, audience=audience, issuer=oidc_issuer)

    with patch("coreason_identity.manager.OIDCProvider") as MockOIDC:
        mock_oidc_instance = MockOIDC.return_value
        mock_oidc_instance.get_jwks = AsyncMock(return_value=jwks)
        mock_oidc_instance.get_issuer = AsyncMock(return_value=oidc_issuer)

        manager = IdentityManagerSync(config)

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": audience,
            "iss": oidc_issuer,  # Matches Config
            "exp": now + 3600,
            "email": "test@example.com",
        }
        token = create_token(key_pair, claims).decode("utf-8")

        # Should PASS
        manager.validate_token(f"Bearer {token}")


def test_validate_token_http_protocol(key_pair: Any, jwks: dict[str, Any]) -> None:
    """Test token with http:// protocol vs https:// config."""
    domain = "test.auth0.com"
    audience = "test-audience"
    config = CoreasonIdentityConfig(domain=domain, audience=audience)

    # Issuer from OIDC Config (HTTPS)
    oidc_issuer = f"https://{domain}/"

    with patch("coreason_identity.manager.OIDCProvider") as MockOIDC:
        mock_oidc_instance = MockOIDC.return_value
        mock_oidc_instance.get_jwks = AsyncMock(return_value=jwks)
        mock_oidc_instance.get_issuer = AsyncMock(return_value=oidc_issuer)

        manager = IdentityManagerSync(config)

        now = int(time.time())
        claims = {
            "sub": "user123",
            "aud": audience,
            "iss": f"http://{domain}/",  # HTTP (mismatch)
            "exp": now + 3600,
            "email": "test@example.com",
        }
        token = create_token(key_pair, claims).decode("utf-8")

        with pytest.raises(CoreasonIdentityError, match="Invalid claim"):
            manager.validate_token(f"Bearer {token}")


def test_init_with_http_protocol_in_domain() -> None:
    """
    Test behavior when domain includes http:// protocol.
    TokenValidator should receive derived issuer (https).
    """
    domain = "http://test.auth0.com"
    config = CoreasonIdentityConfig(domain=domain, audience="aud")

    with (
        patch("coreason_identity.manager.OIDCProvider"),
        patch("coreason_identity.manager.TokenValidator") as MockValidator,
    ):
        IdentityManagerSync(config)

        MockValidator.assert_called_once()
        _, kwargs = MockValidator.call_args
        assert kwargs["issuer"] == "https://test.auth0.com/"
