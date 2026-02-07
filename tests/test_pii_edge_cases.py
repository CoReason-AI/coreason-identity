# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import hashlib
import hmac
from unittest.mock import Mock

import pytest
from pydantic import SecretStr

from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


class TestPiiAnonymizationEdgeCases:
    @pytest.fixture
    def mock_oidc_provider(self) -> Mock:
        return Mock(spec=OIDCProvider)

    def test_empty_string_salt(self, mock_oidc_provider: Mock) -> None:
        """Test with empty string salt (should work but be weak)."""
        salt = ""
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt))

        user_id = "user123"
        hash_val = validator._anonymize(user_id)

        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()
        assert hash_val == expected
        assert hash_val != ""

    def test_whitespace_salt(self, mock_oidc_provider: Mock) -> None:
        """Test with whitespace-only salt."""
        salt = "   "
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt))

        user_id = "user123"
        hash_val = validator._anonymize(user_id)

        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()
        assert hash_val == expected

    def test_special_chars_salt(self, mock_oidc_provider: Mock) -> None:
        """Test with special characters in salt."""
        salt = "!@#$%^&*()_+-=[]{}|;':,./<>?"
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt))

        user_id = "user123"
        hash_val = validator._anonymize(user_id)

        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()
        assert hash_val == expected

    def test_unicode_salt(self, mock_oidc_provider: Mock) -> None:
        """Test with Unicode characters (emoji, non-ascii) in salt."""
        salt = "🔐🧂salt_with_emoji_ñ"
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt))

        user_id = "user123"
        hash_val = validator._anonymize(user_id)

        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()
        assert hash_val == expected

    def test_very_long_salt(self, mock_oidc_provider: Mock) -> None:
        """Test with a very long salt."""
        salt = "a" * 10000
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt))

        user_id = "user123"
        hash_val = validator._anonymize(user_id)

        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()
        assert hash_val == expected

    def test_unicode_user_id(self, mock_oidc_provider: Mock) -> None:
        """Test hashing of a user ID containing unicode characters."""
        salt = "test-salt"
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt))

        user_id = "user_🚀_ñ"
        hash_val = validator._anonymize(user_id)

        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()
        assert hash_val == expected
