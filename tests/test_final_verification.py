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
Final verification tests covering complex scenarios and edge cases identified during final review.
"""

import json
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from authlib.jose.errors import BadSignatureError, JoseError
from httpx import Request, Response
from pydantic import SecretStr

from coreason_identity.device_flow_client import DeviceFlowClient
from coreason_identity.exceptions import (
    CoreasonIdentityError,
    SignatureVerificationError,
)
from coreason_identity.identity_mapper import IdentityMapper
from coreason_identity.models import DeviceFlowResponse
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.validator import TokenValidator


# --- Helper ---
def create_response(status_code: int, json_data: Any = None) -> Response:
    request = Request("GET", "https://example.com")
    return Response(status_code, json=json_data, request=request)


class MockResponse:
    def __init__(self, status_code: int, json_data: Any | None = None, content: bytes | None = None) -> None:
        self.status_code = status_code
        self._json = json_data
        self._content = content
        self.headers = {}

        body = b""
        if json_data is not None:
            body = json.dumps(json_data).encode("utf-8")
        elif content is not None:
            body = content

        self.headers["Content-Length"] = str(len(body))
        self._body = body

    async def aiter_bytes(self) -> AsyncGenerator[bytes, None]:
        yield self._body

    def json(self) -> Any:
        if self._json is not None:
            return self._json
        if self._content:
            return json.loads(self._content)
        raise ValueError("No content")

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("Error", request=None, response=self)  # type: ignore


def setup_stream_mock(mock_client: AsyncMock, responses: list[MockResponse] | MockResponse) -> None:
    if not isinstance(responses, list):
        responses = [responses]

    response_iter = iter(responses)

    @asynccontextmanager
    async def mock_stream(_method: str, _url: str, **_kwargs: Any) -> AsyncGenerator[MockResponse, None]:
        try:
            yield next(response_iter)
        except StopIteration:
            yield MockResponse(500, content=b"Unexpected End of Mock Stream")

    mock_client.stream.side_effect = mock_stream


# --- 1. TokenValidator Verification ---


@pytest.mark.asyncio
async def test_validator_retry_fails() -> None:
    """
    Verify that if validation fails (BadSignature), and we refresh keys,
    and it STILL fails, we raise SignatureVerificationError (not suppressing it).
    """
    mock_provider = MagicMock(spec=OIDCProvider)
    mock_provider.get_jwks = AsyncMock(return_value={"keys": []})  # Empty keys

    validator = TokenValidator(
        mock_provider,
        audience="aud",
        issuer="https://test-issuer.com",
        pii_salt=SecretStr("test-salt"),
        allowed_algorithms=["RS256"],
    )

    # Mock internal JWT decode
    with patch("authlib.jose.JsonWebToken.decode") as mock_decode:
        # First call fails, Second call (after refresh) also fails
        mock_decode.side_effect = BadSignatureError("bad_signature")

        # The error string from Authlib might contain "bad_signature: " or similar
        with pytest.raises(SignatureVerificationError, match=r"Invalid signature:.*bad_signature"):
            await validator.validate_token("bad_token")

    # Ensure refresh was called
    mock_provider.get_jwks.assert_called_with(force_refresh=True)


@pytest.mark.asyncio
async def test_validator_refresh_network_error() -> None:
    """
    Verify that if the first validation fails (triggering refresh),
    and the REFRESH itself throws a network error, that error bubbles up
    (possibly wrapped or as CoreasonIdentityError).
    """
    mock_provider = MagicMock(spec=OIDCProvider)
    # First call succeeds (returns stale keys), Second call fails
    # We need to set side_effect on the AsyncMock
    mock_provider.get_jwks = AsyncMock(
        side_effect=[
            {"keys": []},  # First call (cached or initial)
            CoreasonIdentityError("Network Down"),  # Second call (force_refresh)
        ]
    )

    validator = TokenValidator(
        mock_provider,
        audience="aud",
        issuer="https://test-issuer.com",
        pii_salt=SecretStr("test-salt"),
        allowed_algorithms=["RS256"],
    )

    with patch("authlib.jose.JsonWebToken.decode") as mock_decode:
        # First decode fails (triggering refresh)
        mock_decode.side_effect = BadSignatureError("Bad signature")

        with pytest.raises(CoreasonIdentityError, match="Network Down"):
            await validator.validate_token("token_triggering_refresh")


@pytest.mark.asyncio
async def test_validator_jose_error_generic() -> None:
    """
    Verify a generic JoseError (not signature/expired) raises InvalidTokenError.
    """
    mock_provider = MagicMock(spec=OIDCProvider)
    mock_provider.get_jwks = AsyncMock(return_value={"keys": []})
    validator = TokenValidator(
        mock_provider,
        audience="aud",
        issuer="https://test-issuer.com",
        pii_salt=SecretStr("test-salt"),
        allowed_algorithms=["RS256"],
    )

    with patch("authlib.jose.JsonWebToken.decode") as mock_decode:
        mock_decode.side_effect = JoseError("Some random JOSE error")

        # Should be wrapped in InvalidTokenError
        # Note: SignatureVerificationError inherits from InvalidTokenError,
        # but here we expect the generic wrap message "Token validation failed: ..."
        with pytest.raises(CoreasonIdentityError, match="Token validation failed: Some random JOSE error"):
            await validator.validate_token("bad_token")


# --- 2. IdentityMapper Verification ---


def test_mapper_nested_groups_safely_handled() -> None:
    """
    Verify that if 'groups' contains a nested list (e.g. [['nested']]),
    the mapper handles it without crashing (converting to string representation).
    It will raise CoreasonIdentityError due to strict enum validation, but shouldn't crash.
    """
    mapper = IdentityMapper()
    # Input with nested list
    claims: dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": [["nested_group"], "project:apollo"],
    }

    # Validation step in RawIdPClaims converts list elements to strings.
    # ["nested_group"] -> "['nested_group']" which is invalid enum.

    with pytest.raises(CoreasonIdentityError):
        mapper.map_claims(claims)


def test_mapper_huge_input_strings() -> None:
    """
    Verify mapper handles extremely large strings (basic DoS check for regex).
    """
    mapper = IdentityMapper()
    huge_string = "a" * 10000 + "project:HIDDEN"
    claims: dict[str, Any] = {
        "sub": "u1",
        "email": "u@e.com",
        "groups": [huge_string],
    }

    start = time.time()
    # Expect validation error due to invalid group string
    with pytest.raises(CoreasonIdentityError):
        mapper.map_claims(claims)
    end = time.time()

    # Ensure it didn't take an absurd amount of time (regex catastrophic backtracking check)
    assert (end - start) < 1.0


# --- 3. DeviceFlowClient Verification ---


@pytest.mark.asyncio
async def test_device_flow_mixed_errors() -> None:
    """
    Test a sequence of: slow_down -> authorization_pending -> expired_token.
    """
    # Need mock client for async
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_oidc_provider = AsyncMock(spec=OIDCProvider)
    client = DeviceFlowClient(
        "id",
        "http://idp",
        client=mock_client,
        oidc_provider=mock_oidc_provider,
        scope="openid profile email",
    )

    # Mock endpoints discovery
    with patch.object(client, "_get_endpoints", return_value={"token_endpoint": "url"}):
        device_resp = DeviceFlowResponse(
            device_code="dc", user_code="uc", verification_uri="url", expires_in=10, interval=1
        )

        responses = [
            MockResponse(400, {"error": "slow_down"}),  # Should sleep interval+5
            MockResponse(400, {"error": "authorization_pending"}),  # Should sleep current interval
            MockResponse(400, {"error": "expired_token"}),  # Should raise error
        ]
        setup_stream_mock(mock_client, responses)

        with patch("anyio.sleep", new_callable=AsyncMock) as mock_sleep:
            with pytest.raises(CoreasonIdentityError, match="Device code expired"):
                await client.poll_token(device_resp)

            # Check sleep calls
            # 1. slow_down: interval 1 -> 6. Sleep(6)
            # 2. auth_pending: interval 6. Sleep(6)
            assert mock_sleep.call_count == 2
            # Arguments to sleep might be int or float depending on implementation
            # Check values approximately or exactly if possible
            assert mock_sleep.call_args_list[0] == ((6,),)
            assert mock_sleep.call_args_list[1] == ((6,),)
