# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import Mock, patch, AsyncMock
import pytest
import httpx
from coreason_identity.exceptions import CoreasonIdentityError
from coreason_identity.oidc_provider import OIDCProvider, OIDCProviderAsync

def create_mock_response(json_data=None, status_code=200):
    mock_resp = Mock()
    mock_resp.status_code = status_code
    if json_data is not None:
        mock_resp.json.return_value = json_data
    mock_resp.raise_for_status.side_effect = (
        None if status_code < 400 else httpx.HTTPStatusError("Error", request=Mock(), response=mock_resp)
    )
    return mock_resp

# --- Async Tests ---

@pytest.fixture
def oidc_provider_async() -> OIDCProviderAsync:
    return OIDCProviderAsync(discovery_url="https://test.auth0.com/.well-known/openid-configuration")

@pytest.mark.asyncio
async def test_async_initialization() -> None:
    provider = OIDCProviderAsync(discovery_url="https://test.auth0.com", cache_ttl=1800)
    assert provider.discovery_url == "https://test.auth0.com"
    assert provider.cache_ttl == 1800
    assert provider._jwks_cache is None

@pytest.mark.asyncio
async def test_async_get_jwks_success(oidc_provider_async: OIDCProviderAsync) -> None:
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.side_effect = [
        create_mock_response({"jwks_uri": "https://test.auth0.com/jwks.json"}),
        create_mock_response({"keys": [{"kid": "1", "kty": "RSA"}]})
    ]

    oidc_provider_async._client = mock_client
    oidc_provider_async._internal_client = False
    await oidc_provider_async.__aenter__()

    jwks = await oidc_provider_async.get_jwks()

    assert jwks == {"keys": [{"kid": "1", "kty": "RSA"}]}
    assert mock_client.get.call_count == 2

@pytest.mark.asyncio
async def test_async_get_jwks_caching(oidc_provider_async: OIDCProviderAsync) -> None:
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.side_effect = [
        create_mock_response({"jwks_uri": "https://test.auth0.com/jwks.json"}),
        create_mock_response({"keys": [{"kid": "1"}]})
    ]

    oidc_provider_async._client = mock_client
    await oidc_provider_async.__aenter__()

    # First fetch
    await oidc_provider_async.get_jwks()
    assert mock_client.get.call_count == 2

    # Second fetch (cached)
    await oidc_provider_async.get_jwks()
    assert mock_client.get.call_count == 2

@pytest.mark.asyncio
async def test_async_fetch_config_fail(oidc_provider_async: OIDCProviderAsync) -> None:
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.side_effect = httpx.HTTPError("Network Error")

    oidc_provider_async._client = mock_client
    await oidc_provider_async.__aenter__()

    with pytest.raises(CoreasonIdentityError, match="Failed to fetch OIDC configuration"):
        await oidc_provider_async.get_jwks()

@pytest.mark.asyncio
async def test_async_fetch_jwks_fail(oidc_provider_async: OIDCProviderAsync) -> None:
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.side_effect = [
        create_mock_response({"jwks_uri": "https://test.auth0.com/jwks.json"}),
        httpx.HTTPError("Network Error")
    ]

    oidc_provider_async._client = mock_client
    await oidc_provider_async.__aenter__()

    with pytest.raises(CoreasonIdentityError, match="Failed to fetch JWKS"):
        await oidc_provider_async.get_jwks()

@pytest.mark.asyncio
async def test_async_missing_jwks_uri(oidc_provider_async: OIDCProviderAsync) -> None:
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get.return_value = create_mock_response({"foo": "bar"}) # Missing jwks_uri

    oidc_provider_async._client = mock_client
    await oidc_provider_async.__aenter__()

    with pytest.raises(CoreasonIdentityError, match="does not contain 'jwks_uri'"):
        await oidc_provider_async.get_jwks()

# --- Sync Facade Tests ---

@pytest.fixture
def oidc_provider_sync() -> OIDCProvider:
    return OIDCProvider(discovery_url="https://test.auth0.com/.well-known/openid-configuration")

def test_sync_get_jwks_success(oidc_provider_sync: OIDCProvider) -> None:
    with patch("coreason_identity.oidc_provider.httpx.AsyncClient") as MockClientCls:
        mock_client = AsyncMock()
        MockClientCls.return_value = mock_client
        mock_client.get.side_effect = [
            create_mock_response({"jwks_uri": "https://test.auth0.com/jwks.json"}),
            create_mock_response({"keys": [{"kid": "1"}]})
        ]

        with oidc_provider_sync as provider:
             jwks = provider.get_jwks()

        assert jwks == {"keys": [{"kid": "1"}]}

def test_sync_usage_without_context_manager_fails(oidc_provider_sync: OIDCProvider) -> None:
    with pytest.raises(CoreasonIdentityError, match="Context not started"):
        oidc_provider_sync.get_jwks()
