# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from typing import Any, Dict
from unittest.mock import Mock, patch

import pytest
from authlib.jose import JsonWebKey, jwt

from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestValidatorKeyRotation:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        return Mock(spec=OIDCProvider)

    @pytest.fixture
    def key_pair_old(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "key-old"})

    @pytest.fixture
    def key_pair_new(self) -> Any:
        return JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "key-new"})

    @pytest.fixture
    def validator(self, mock_oidc_provider: Mock) -> TokenValidator:
        return TokenValidator(
            oidc_provider=mock_oidc_provider,
            audience="my-audience",
            issuer="https://issuer.com/",
        )

    def create_token(self, key: Any, claims: Dict[str, Any]) -> str:
        headers = {"alg": "RS256", "kid": key.as_dict()["kid"]}
        return jwt.encode(headers, claims, key).decode("utf-8")  # type: ignore[no-any-return]

    def test_key_rotation_refresh_flow(
        self,
        validator: TokenValidator,
        mock_oidc_provider: Mock,
        key_pair_old: Any,
        key_pair_new: Any,
    ) -> None:
        """
        Test that validation fails with old keys, triggers refresh, and succeeds with new keys.
        """
        # Initial State: JWKS has only the old key
        jwks_old = {"keys": [key_pair_old.as_dict(private=False)]}
        jwks_new = {"keys": [key_pair_new.as_dict(private=False)]}

        # Setup mock behavior
        # First call (cached or initial): returns old keys
        # Second call (force_refresh=True): returns new keys
        def get_jwks_side_effect(force_refresh: bool = False) -> Dict[str, Any]:
            if force_refresh:
                return jwks_new
            return jwks_old

        mock_oidc_provider.get_jwks.side_effect = get_jwks_side_effect

        # Create a token signed by the NEW key
        claims = {
            "sub": "user123",
            "aud": "my-audience",
            "iss": "https://issuer.com/",
            "exp": 9999999999,
        }
        token = self.create_token(key_pair_new, claims)

        # Execute validation
        # We expect this to succeed internally by catching BadSignatureError/ValueError and retrying
        payload = validator.validate_token(token)

        assert payload["sub"] == "user123"

        # Verify interaction
        # Should have called get_jwks() initially (or from cache)
        # And then get_jwks(force_refresh=True)
        calls = mock_oidc_provider.get_jwks.call_args_list
        assert len(calls) >= 2
        # Check that at least one call had force_refresh=True
        assert any(call.kwargs.get("force_refresh") is True for call in calls)

    @patch("coreason_identity.validator.tracer")
    def test_key_rotation_emits_telemetry(
        self,
        mock_tracer: Mock,
        validator: TokenValidator,
        mock_oidc_provider: Mock,
        key_pair_old: Any,
        key_pair_new: Any,
    ) -> None:
        """
        Test that the 'refreshing_jwks' event is added to the span.
        """
        # Setup similar to above
        jwks_old = {"keys": [key_pair_old.as_dict(private=False)]}
        jwks_new = {"keys": [key_pair_new.as_dict(private=False)]}

        mock_oidc_provider.get_jwks.side_effect = lambda force_refresh=False: jwks_new if force_refresh else jwks_old

        token = self.create_token(
            key_pair_new, {"sub": "u", "aud": "my-audience", "iss": "https://issuer.com/", "exp": 9999999999}
        )

        # Capture the span
        mock_span = Mock()
        mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

        validator.validate_token(token)

        # Verify event was added
        mock_span.add_event.assert_any_call("refreshing_jwks")
