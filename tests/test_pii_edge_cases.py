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

    def test_empty_user_id(self, mock_oidc_provider: Mock) -> None:
        """
        Edge Case 1: Empty User ID.
        Verify it hashes correctly (empty message HMAC) and doesn't crash.
        """
        salt = "test-salt"
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt), issuer="https://default-issuer.com", allowed_algorithms=["RS256"])

        user_id = ""
        anonymized = validator._anonymize(user_id)

        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()

        assert anonymized == expected

    def test_null_byte_in_user_id(self, mock_oidc_provider: Mock) -> None:
        """
        Edge Case 2: Null Byte in User ID.
        Ensure \\x00 is handled correctly (Python strings handle nulls fine, but HMAC ensures no truncation issues).
        """
        salt = "test-salt"
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt), issuer="https://default-issuer.com", allowed_algorithms=["RS256"])

        user_id = "user\x00with\x00nulls"
        anonymized = validator._anonymize(user_id)

        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()

        assert anonymized == expected

    def test_long_user_id(self, mock_oidc_provider: Mock) -> None:
        """
        Edge Case 3: Extremely Long User ID.
        Verify correct hashing for large payloads.
        """
        salt = "test-salt"
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt), issuer="https://default-issuer.com", allowed_algorithms=["RS256"])

        # 100KB string
        user_id = "a" * 100_000
        anonymized = validator._anonymize(user_id)

        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()

        assert anonymized == expected

    def test_unicode_salt(self, mock_oidc_provider: Mock) -> None:
        """
        Edge Case 4: Unicode Salt.
        Ensure the configuration and HMAC handle non-ASCII characters in the salt.
        """
        salt = "s@lt_🚀_ñ"
        validator = TokenValidator(oidc_provider=mock_oidc_provider, audience="aud", pii_salt=SecretStr(salt), issuer="https://default-issuer.com", allowed_algorithms=["RS256"])

        user_id = "user123"
        anonymized = validator._anonymize(user_id)

        expected = hmac.new(salt.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()

        assert anonymized == expected
