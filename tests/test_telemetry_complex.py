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
import time
from typing import Any, List, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from authlib.jose.errors import BadSignatureError
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.utils.logger import logger
from coreason_identity.validator import TokenValidator
from opentelemetry.sdk.trace import Tracer, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


class MockClaims(dict[str, Any]):
    def validate(self) -> None:
        pass


@pytest.fixture
def telemetry_setup() -> Tuple[InMemorySpanExporter, Tracer]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    processor = SimpleSpanProcessor(exporter)
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("test_tracer_complex")
    return exporter, tracer  # type: ignore[return-value]


@pytest.fixture
def mock_oidc_provider() -> MagicMock:
    provider = MagicMock(spec=OIDCProvider)
    jwks = {"keys": [{"kty": "RSA", "kid": "123", "n": "abc", "e": "AQAB"}]}
    provider.get_jwks = AsyncMock(return_value=jwks)
    return provider


@pytest.mark.asyncio
async def test_telemetry_context_propagation(
    telemetry_setup: Tuple[InMemorySpanExporter, Tracer],
    mock_oidc_provider: MagicMock,
) -> None:
    """Verifies that the validation span is correctly parented if a span is active."""
    exporter, tracer = telemetry_setup
    audience = "test-audience"

    with patch("coreason_identity.validator.tracer", tracer):
        validator = TokenValidator(mock_oidc_provider, audience)
        claims = MockClaims({"sub": "user123", "aud": audience, "exp": time.time() + 3600})

        with patch("authlib.jose.JsonWebToken.decode", return_value=claims):
            with tracer.start_as_current_span("parent_span") as parent_span:
                await validator.validate_token("dummy_token")
                parent_context = parent_span.get_span_context()

    spans = exporter.get_finished_spans()
    # Should have 2 spans: parent and child
    assert len(spans) == 2
    child_span = next(s for s in spans if s.name == "validate_token")
    assert child_span.parent is not None
    assert child_span.parent.span_id == parent_context.span_id
    assert child_span.parent.trace_id == parent_context.trace_id


@pytest.mark.asyncio
async def test_telemetry_jwks_refresh_event(
    telemetry_setup: Tuple[InMemorySpanExporter, Tracer],
    mock_oidc_provider: MagicMock,
) -> None:
    """Verifies that the 'refreshing_jwks' event is added when retry logic triggers."""
    exporter, tracer = telemetry_setup
    audience = "test-audience"

    with patch("coreason_identity.validator.tracer", tracer):
        validator = TokenValidator(mock_oidc_provider, audience)
        claims = MockClaims({"sub": "user123", "aud": audience, "exp": time.time() + 3600})

        # Simulate first decode failing with BadSignatureError, then second succeeding
        with patch("authlib.jose.JsonWebToken.decode") as mock_decode:
            mock_decode.side_effect = [BadSignatureError("bad sig"), claims]

            await validator.validate_token("dummy_token")

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]

    # Check for event
    event_names = [e.name for e in span.events]
    assert "refreshing_jwks" in event_names
    # Verify force_refresh was called
    mock_oidc_provider.get_jwks.assert_called_with(force_refresh=True)


@pytest.mark.asyncio
async def test_telemetry_unicode_user_id(
    telemetry_setup: Tuple[InMemorySpanExporter, Tracer],
    mock_oidc_provider: MagicMock,
    # caplog: pytest.LogCaptureFixture,
) -> None:
    """Verifies handling of Unicode/Complex user IDs."""

    # Setup custom log capture because loguru
    logs: List[Any] = []
    logger.add(logs.append, level="INFO", format="{message}")

    exporter, tracer = telemetry_setup
    audience = "test-audience"
    # User ID with emoji and non-ascii
    user_id = "user_🚀_ñ"

    with patch("coreason_identity.validator.tracer", tracer):
        validator = TokenValidator(mock_oidc_provider, audience)
        claims = MockClaims({"sub": user_id, "aud": audience, "exp": time.time() + 3600})

        with patch("authlib.jose.JsonWebToken.decode", return_value=claims):
            await validator.validate_token("dummy_token")

    spans = exporter.get_finished_spans()
    span = spans[0]
    # Check attribute
    assert span.attributes is not None
    assert span.attributes["user.id"] == user_id

    # Check log hash
    expected_hash = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
    assert any(f"Token validated for user {expected_hash}" in record.record["message"] for record in logs)


@pytest.mark.asyncio
async def test_telemetry_noop_tracer_safety(mock_oidc_provider: MagicMock) -> None:
    """Verifies that the code runs safely with a ProxyTracer (No-Op)."""
    # Simply use trace.get_tracer without setting a provider, it returns a ProxyTracer/NoOp
    # We need to make sure we are not using the global one set by other tests
    # But other tests set the global provider using trace.set_tracer_provider?
    # Actually pytest fixtures often isolate, but here they might leak if set_tracer_provider is global.
    # We can just get a tracer from a fresh provider that has NO processors.

    provider = TracerProvider()
    noop_tracer = provider.get_tracer("noop_tracer")

    audience = "test-audience"

    with patch("coreason_identity.validator.tracer", noop_tracer):
        validator = TokenValidator(mock_oidc_provider, audience)
        claims = MockClaims({"sub": "user123", "aud": audience, "exp": time.time() + 3600})

        with patch("authlib.jose.JsonWebToken.decode", return_value=claims):
            # Should not raise any exception
            await validator.validate_token("dummy_token")
