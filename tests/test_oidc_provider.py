# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import Mock, patch

import httpx
import pytest
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.oidc_provider import OIDCProvider
from httpx import Response


@pytest.fixture
def oidc_provider() -> OIDCProvider:
    return OIDCProvider(discovery_url="https://test.auth0.com/.well-known/openid-configuration")


def test_initialization() -> None:
    provider = OIDCProvider(discovery_url="https://test.auth0.com/.well-known/openid-configuration", cache_ttl=1800)
    assert provider.discovery_url == "https://test.auth0.com/.well-known/openid-configuration"
    assert provider.cache_ttl == 1800
    assert provider._jwks_cache is None
    assert provider._last_update == 0.0


@patch("httpx.Client.get")
def test_get_jwks_success(mock_get: Mock, oidc_provider: OIDCProvider) -> None:
    # Setup mocks
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"jwks_uri": "https://test.auth0.com/.well-known/jwks.json"}

    mock_jwks_response = Mock(spec=Response)
    mock_jwks_response.raise_for_status.return_value = None
    mock_jwks_response.json.return_value = {"keys": [{"kid": "123", "kty": "RSA"}]}

    # Configure side_effect for consecutive calls
    mock_get.side_effect = [mock_config_response, mock_jwks_response]

    # Execute
    jwks = oidc_provider.get_jwks()

    # Verify
    assert jwks == {"keys": [{"kid": "123", "kty": "RSA"}]}
    assert oidc_provider._jwks_cache == jwks
    assert oidc_provider._last_update > 0.0
    assert mock_get.call_count == 2
    mock_get.assert_any_call("https://test.auth0.com/.well-known/openid-configuration")
    mock_get.assert_any_call("https://test.auth0.com/.well-known/jwks.json")


@patch("httpx.Client.get")
def test_get_jwks_caching(mock_get: Mock, oidc_provider: OIDCProvider) -> None:
    # Setup mocks
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"jwks_uri": "https://test.auth0.com/.well-known/jwks.json"}

    mock_jwks_response = Mock(spec=Response)
    mock_jwks_response.raise_for_status.return_value = None
    mock_jwks_response.json.return_value = {"keys": [{"kid": "123", "kty": "RSA"}]}

    mock_get.side_effect = [mock_config_response, mock_jwks_response]

    # First call - fetches from network
    jwks1 = oidc_provider.get_jwks()
    assert mock_get.call_count == 2

    # Second call - should use cache
    jwks2 = oidc_provider.get_jwks()
    assert jwks1 == jwks2
    assert mock_get.call_count == 2  # Count should remain 2


@patch("httpx.Client.get")
def test_get_jwks_force_refresh(mock_get: Mock, oidc_provider: OIDCProvider) -> None:
    # Setup mocks
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"jwks_uri": "https://test.auth0.com/.well-known/jwks.json"}

    mock_jwks_response = Mock(spec=Response)
    mock_jwks_response.raise_for_status.return_value = None
    mock_jwks_response.json.return_value = {"keys": [{"kid": "123", "kty": "RSA"}]}

    # We expect 2 cycles of calls (config, jwks, config, jwks)
    mock_get.side_effect = [mock_config_response, mock_jwks_response, mock_config_response, mock_jwks_response]

    # First call
    oidc_provider.get_jwks()
    assert mock_get.call_count == 2

    # Force refresh
    oidc_provider.get_jwks(force_refresh=True)
    assert mock_get.call_count == 4


@patch("httpx.Client.get")
def test_get_jwks_cache_expiration(mock_get: Mock, oidc_provider: OIDCProvider) -> None:
    # Setup mocks
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"jwks_uri": "https://test.auth0.com/.well-known/jwks.json"}

    mock_jwks_response = Mock(spec=Response)
    mock_jwks_response.raise_for_status.return_value = None
    mock_jwks_response.json.return_value = {"keys": [{"kid": "123", "kty": "RSA"}]}

    mock_get.side_effect = [mock_config_response, mock_jwks_response, mock_config_response, mock_jwks_response]

    # Set a short TTL for testing
    oidc_provider.cache_ttl = 0.1  # type: ignore[assignment]

    # First call
    oidc_provider.get_jwks()
    assert mock_get.call_count == 2

    # Manually expire the cache
    import time

    oidc_provider._last_update = float(time.time() - 4000)
    oidc_provider.cache_ttl = 3600

    # Second call - should refetch
    oidc_provider.get_jwks()
    assert mock_get.call_count == 4


@patch("httpx.Client.get")
def test_fetch_oidc_config_failure(mock_get: Mock, oidc_provider: OIDCProvider) -> None:
    mock_get.side_effect = httpx.HTTPError("Network error")

    with pytest.raises(CoreasonIdentityError) as exc_info:
        oidc_provider.get_jwks()

    assert "Failed to fetch OIDC configuration" in str(exc_info.value)


@patch("httpx.Client.get")
def test_fetch_jwks_failure(mock_get: Mock, oidc_provider: OIDCProvider) -> None:
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"jwks_uri": "https://test.auth0.com/.well-known/jwks.json"}

    mock_get.side_effect = [mock_config_response, httpx.HTTPError("Network error")]

    with pytest.raises(CoreasonIdentityError) as exc_info:
        oidc_provider.get_jwks()

    assert "Failed to fetch JWKS" in str(exc_info.value)


@patch("httpx.Client.get")
def test_missing_jwks_uri(mock_get: Mock, oidc_provider: OIDCProvider) -> None:
    mock_config_response = Mock(spec=Response)
    mock_config_response.raise_for_status.return_value = None
    mock_config_response.json.return_value = {"other_field": "value"}

    mock_get.return_value = mock_config_response

    with pytest.raises(CoreasonIdentityError) as exc_info:
        oidc_provider.get_jwks()

    assert "OIDC configuration does not contain 'jwks_uri'" in str(exc_info.value)
