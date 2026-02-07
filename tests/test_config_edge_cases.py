# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import os
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

from coreason_identity.config import CoreasonIdentityConfig


class TestConfigEdgeCases:
    """Test suite for edge cases in CoreasonIdentityConfig validation."""

    def test_http_timeout_zero(self) -> None:
        """Test that http_timeout=0.0 is technically allowed by Pydantic (float) but might be dangerous."""
        # Pydantic validates type, but logic should handle it. httpx interprets 0.0 as instant timeout or invalid.
        # We don't enforce > 0 in config validator yet, but verify it passes schema.
        config = CoreasonIdentityConfig(domain="test.com", audience="aud", http_timeout=0.0)
        assert config.http_timeout == 0.0

    def test_http_timeout_negative(self) -> None:
        """Test that negative timeout is allowed by schema (float) but might be invalid for httpx."""
        # Pydantic allows negative floats unless constrained.
        # httpx might raise ValueError later, but config allows it.
        config = CoreasonIdentityConfig(domain="test.com", audience="aud", http_timeout=-1.0)
        assert config.http_timeout == -1.0

    def test_http_timeout_extremely_small(self) -> None:
        """Test extremely small timeout values."""
        config = CoreasonIdentityConfig(domain="test.com", audience="aud", http_timeout=1e-6)
        assert config.http_timeout == 1e-6

    def test_unsafe_local_dev_env_var_parsing(self) -> None:
        """Test parsing boolean env vars for unsafe_local_dev."""
        # 'true', 'True', '1' -> True
        with patch.dict(
            os.environ,
            {
                "COREASON_AUTH_HTTP_TIMEOUT": "5.0",
                "COREASON_AUTH_UNSAFE_LOCAL_DEV": "true",
            },
        ):
            config = CoreasonIdentityConfig(domain="test.com", audience="aud")
            assert config.unsafe_local_dev is True

        with patch.dict(
            os.environ,
            {
                "COREASON_AUTH_HTTP_TIMEOUT": "5.0",
                "COREASON_AUTH_UNSAFE_LOCAL_DEV": "1",
            },
        ):
            config = CoreasonIdentityConfig(domain="test.com", audience="aud")
            assert config.unsafe_local_dev is True

    def test_unsafe_local_dev_false_env_vars(self) -> None:
        """Test parsing false values for unsafe_local_dev."""
        # 'false', '0' -> False
        with patch.dict(
            os.environ,
            {
                "COREASON_AUTH_HTTP_TIMEOUT": "5.0",
                "COREASON_AUTH_UNSAFE_LOCAL_DEV": "false",
            },
        ):
            config = CoreasonIdentityConfig(domain="test.com", audience="aud")
            assert config.unsafe_local_dev is False

    def test_unsafe_local_dev_enabled_with_https(self) -> None:
        """Test that unsafe_local_dev=True does NOT break HTTPS issuers."""
        config = CoreasonIdentityConfig(
            domain="test.com",
            audience="aud",
            http_timeout=5.0,
            unsafe_local_dev=True,
            issuer="https://secure.provider.com",
        )
        assert config.issuer == "https://secure.provider.com"

    def test_unsafe_local_dev_disabled_implicit_http_domain(self) -> None:
        """
        Test behavior when issuer is auto-generated from an HTTP domain.
        The normalization logic adds https:// if missing, but if user provides http:// explicitly in domain?
        CoreasonIdentityConfig.normalize_domain handles the domain field.
        """
        # Case 1: domain="http://test.com" -> normalized to "test.com" -> issuer defaults to "https://test.com/"
        # This is safe.
        config = CoreasonIdentityConfig(domain="http://test.com", audience="aud", http_timeout=5.0)
        assert config.domain == "test.com"
        assert config.issuer == "https://test.com/"

        # Case 2: domain="test.com" -> normalized to "test.com" -> issuer defaults to "https://test.com/"
        config2 = CoreasonIdentityConfig(domain="test.com", audience="aud", http_timeout=5.0)
        assert config2.issuer == "https://test.com/"

    def test_explicit_http_issuer_without_flag(self) -> None:
        """Test that explicitly setting http issuer fails without flag, even if domain is safe."""
        with pytest.raises(ValidationError, match="HTTPS is required"):
            CoreasonIdentityConfig(
                domain="test.com",
                audience="aud",
                http_timeout=5.0,
                issuer="http://test.com",
            )

    def test_empty_salt_accepted(self) -> None:
        """
        Edge Case: Empty string salt.
        Currently, SecretStr allows empty strings.
        This test documents the behavior.
        """
        with patch.dict(os.environ, {"COREASON_AUTH_PII_SALT": ""}):
            config = CoreasonIdentityConfig(domain="test.com", audience="aud")
            assert config.pii_salt.get_secret_value() == ""

    def test_whitespace_salt_preserved(self) -> None:
        """Edge Case: Whitespace salt."""
        salt = "   "
        with patch.dict(os.environ, {"COREASON_AUTH_PII_SALT": salt}):
            config = CoreasonIdentityConfig(domain="test.com", audience="aud")
            assert config.pii_salt.get_secret_value() == salt

    def test_salt_precedence_constructor_over_env(self) -> None:
        """Complex Case: Constructor argument should override environment variable."""
        env_salt = "env-salt"
        arg_salt = "arg-salt"
        with patch.dict(os.environ, {"COREASON_AUTH_PII_SALT": env_salt}):
            config = CoreasonIdentityConfig(
                domain="test.com", audience="aud", pii_salt=SecretStr(arg_salt)
            )
            assert config.pii_salt.get_secret_value() == arg_salt

    def test_unsafe_local_dev_does_not_bypass_salt(self) -> None:
        """Complex Case: unsafe_local_dev should not make pii_salt optional."""
        with patch.dict(os.environ):
            if "COREASON_AUTH_PII_SALT" in os.environ:
                del os.environ["COREASON_AUTH_PII_SALT"]

            # Even with unsafe_local_dev=True, it should fail
            with pytest.raises(ValidationError) as exc:
                CoreasonIdentityConfig(
                    domain="test.com", audience="aud", unsafe_local_dev=True
                )
            assert "pii_salt" in str(exc.value)

    def test_multiple_configs_independent_salts(self) -> None:
        """Complex Case: Multiple config instances can have different salts."""
        c1 = CoreasonIdentityConfig(
            domain="d1.com", audience="a1", pii_salt=SecretStr("salt1")
        )
        c2 = CoreasonIdentityConfig(
            domain="d2.com", audience="a2", pii_salt=SecretStr("salt2")
        )

        assert c1.pii_salt.get_secret_value() == "salt1"
        assert c2.pii_salt.get_secret_value() == "salt2"
