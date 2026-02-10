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
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from authlib.jose.errors import ExpiredTokenError
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode, Tracer
from pydantic import SecretStr

from coreason_identity.exceptions import TokenExpiredError
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.utils.logger import logger
from coreason_identity.validator import TokenValidator


class MockClaims(dict[str, Any]):
    """Helper to mock Authlib claims which behave like a dict but have a validate method."""

    def validate(self, *args: Any, **kwargs: Any) -> None:
        pass


@pytest.fixture
def telemetry_setup() -> tuple[InMemorySpanExporter, Tracer]:
    """Sets up an OpenTelemetry tracer with an in-memory exporter."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    processor = SimpleSpanProcessor(exporter)
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("test_tracer")
    return exporter, tracer


@pytest.fixture
def mock_oidc_provider() -> MagicMock:
    provider = MagicMock(spec=OIDCProvider)
    # Mock public key
    jwks = {"keys": [{"kty": "RSA", "kid": "123", "n": "abc", "e": "AQAB"}]}
    provider.get_jwks = AsyncMock(return_value=jwks)
    return provider


@pytest.mark.asyncio
async def test_validate_token_success_telemetry(
    telemetry_setup: tuple[InMemorySpanExporter, Tracer],
    mock_oidc_provider: MagicMock,
) -> None:
    """Verifies that a successful validation emits a correct span."""
    exporter, tracer = telemetry_setup
    audience = "test-audience"

    # Patch the module-level tracer
    with patch("coreason_identity.validator.tracer", tracer):
        validator = TokenValidator(
            mock_oidc_provider,
            audience,
            issuer="https://test-issuer.com",
            pii_salt=SecretStr("test-salt"),
            allowed_algorithms=["RS256"],
        )

        # Mock JWT decode to succeed
        claims = MockClaims(
            {"iss": "https://test-issuer.com", "sub": "user123", "aud": audience, "exp": time.time() + 3600}
        )

        with patch("authlib.jose.JsonWebToken.decode") as mock_decode:
            mock_decode.return_value = claims
            await validator.validate_token("dummy_token")

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "validate_token"
    assert span.status.status_code == StatusCode.OK
    # The attributes might be None if empty, but we set it, so it should be a BoundedAttributes
    assert span.attributes is not None
    expected_hash = hmac.new(b"test-salt", b"user123", hashlib.sha256).hexdigest()
    assert span.attributes["enduser.id"] == expected_hash


@pytest.mark.asyncio
async def test_validate_token_failure_telemetry(
    telemetry_setup: tuple[InMemorySpanExporter, Tracer],
    mock_oidc_provider: MagicMock,
) -> None:
    """Verifies that a failed validation emits an error span."""
    exporter, tracer = telemetry_setup
    audience = "test-audience"

    with patch("coreason_identity.validator.tracer", tracer):
        validator = TokenValidator(
            mock_oidc_provider,
            audience,
            issuer="https://test-issuer.com",
            pii_salt=SecretStr("test-salt"),
            allowed_algorithms=["RS256"],
        )

        # Mock JWT decode to raise ExpiredTokenError
        with patch("authlib.jose.JsonWebToken.decode") as mock_decode:
            mock_decode.side_effect = ExpiredTokenError("expired", "exp")

            with pytest.raises(TokenExpiredError):
                await validator.validate_token("expired_token")

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "validate_token"
    assert span.status.status_code == StatusCode.ERROR
    # Exception recording depends on SDK implementation details, but usually events are added
    assert len(span.events) > 0
    assert span.events[0].name == "exception"


@pytest.mark.asyncio
async def test_logging_strictness(mock_oidc_provider: MagicMock) -> None:
    """Verifies that the user ID is hashed in the logs."""
    # Ensure we capture logs from our logger
    # logger.add(caplog.handler, level="INFO")
    # Note: adding caplog.handler might duplicate if pytest handles it, but loguru needs explicit hook often.
    # However, standard pytest caplog might not catch loguru unless we sink it.

    # We'll sink to a list to be sure
    logs: list[Any] = []
    logger.add(logs.append, level="INFO", format="{message}")

    audience = "test-audience"
    validator = TokenValidator(
        mock_oidc_provider,
        audience,
        issuer="https://test-issuer.com",
        pii_salt=SecretStr("test-salt"),
        allowed_algorithms=["RS256"],
    )
    user_id = "sensitive-user-id"

    # Mock JWT decode to succeed
    claims = MockClaims({"iss": "https://test-issuer.com", "sub": user_id, "aud": audience, "exp": time.time() + 3600})
    with patch("authlib.jose.JsonWebToken.decode") as mock_decode:
        mock_decode.return_value = claims
        await validator.validate_token("dummy_token")

    # Calculate expected hash
    expected_hash = hmac.new(b"test-salt", user_id.encode("utf-8"), hashlib.sha256).hexdigest()

    # Check if the message is in the captured logs
    assert any(f"Token validated for user {expected_hash}" in record.record["message"] for record in logs)

    # Ensure raw ID is NOT logged in the message
    assert not any(user_id in record.record["message"] for record in logs)
