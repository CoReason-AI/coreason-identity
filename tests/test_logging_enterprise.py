# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import json
import logging
import os
from typing import Any
from unittest.mock import patch

import pytest
from loguru import logger
from opentelemetry.sdk.trace import TracerProvider

from coreason_identity.utils.logger import configure_logging


@pytest.fixture
def capture_logs(capfd: pytest.CaptureFixture[str]) -> pytest.CaptureFixture[str]:
    """Fixture to capture stdout/stderr."""
    return capfd


def test_json_configuration(capture_logs: pytest.CaptureFixture[str]) -> None:
    """Test that setting COREASON_LOG_JSON=true produces JSON output."""
    with patch.dict(os.environ, {"COREASON_LOG_JSON": "true", "COREASON_LOG_LEVEL": "INFO"}):
        configure_logging()

        logger.info("Test JSON message")

        out, err = capture_logs.readouterr()
        # Loguru logs to stdout when JSON is enabled in our config

        # VERIFY FIX: Ensure no logs in stderr (no duplicates)
        assert not err, f"Stderr should be empty when JSON enabled, but got: {err}"

        assert out
        lines = out.strip().split("\n")
        # We might have other logs, get the last one or search
        found = False
        for line in lines:
            if "Test JSON message" in line:
                try:
                    log_entry = json.loads(line)
                    # Loguru default serialization structure
                    record = log_entry["record"]
                    assert record["message"] == "Test JSON message"
                    assert record["level"]["name"] == "INFO"
                    found = True
                except (json.JSONDecodeError, KeyError):
                    pass

        assert found, f"JSON log entry not found in output: {out}"


def test_trace_id_injection(capture_logs: pytest.CaptureFixture[str]) -> None:
    """Test that trace IDs are injected into logs."""
    # Setup OTEL
    provider = TracerProvider()
    tracer = provider.get_tracer(__name__)

    with patch.dict(os.environ, {"COREASON_LOG_JSON": "true"}):
        configure_logging()

        with tracer.start_as_current_span("test_span") as span:
            logger.info("Trace message")

            ctx = span.get_span_context()
            trace_id = format(ctx.trace_id, "032x")
            span_id = format(ctx.span_id, "016x")

            out, _ = capture_logs.readouterr()
            assert out
            lines = out.strip().split("\n")
            found = False
            for line in lines:
                if "Trace message" in line:
                    try:
                        log_entry = json.loads(line)
                        record = log_entry.get("record", {})
                        extra = record.get("extra", {})
                        assert extra.get("trace_id") == trace_id
                        assert extra.get("span_id") == span_id
                        assert extra.get("correlation_id") == trace_id
                        found = True
                    except (json.JSONDecodeError, KeyError):
                        pass
            assert found, "Log entry with trace message not found or invalid JSON"


def test_standard_logging_interception(capture_logs: pytest.CaptureFixture[str]) -> None:
    """Test that standard logging messages are intercepted."""
    with patch.dict(os.environ, {"COREASON_LOG_JSON": "true"}):
        configure_logging()

        # Use standard logging
        logging.info("Standard logging message")

        out, _ = capture_logs.readouterr()
        assert out

        found = False
        for line in out.strip().split("\n"):
            if "Standard logging message" in line:
                try:
                    log_entry = json.loads(line)
                    record = log_entry["record"]
                    assert record["message"] == "Standard logging message"
                    assert record["level"]["name"] == "INFO"
                    found = True
                except (json.JSONDecodeError, KeyError):
                    pass
        assert found, "Standard logging message not intercepted correctly"


def test_default_text_logging(capture_logs: pytest.CaptureFixture[str]) -> None:
    """Test default human readable logging."""
    with patch.dict(os.environ, {"COREASON_LOG_JSON": "false"}):
        configure_logging()

        logger.info("Text message")

        _, err = capture_logs.readouterr()
        # Stderr is used for text logging in our config
        assert err
        assert "Text message" in err

        # Ensure it's not JSON (simple check)
        assert not err.strip().startswith("{") or not err.strip().endswith("}")


def test_invalid_log_level_fallback() -> None:
    """Test that invalid log level falls back to INFO."""
    with patch.dict(os.environ, {"COREASON_LOG_LEVEL": "INVALID_LEVEL"}):
        configure_logging()
        # Verify root logger level is INFO (20)
        assert logging.getLogger().level == logging.INFO


def test_custom_log_level_interception(capture_logs: pytest.CaptureFixture[str]) -> None:
    """Test interception of a custom log level (triggers ValueError path in handler)."""
    with patch.dict(os.environ, {"COREASON_LOG_JSON": "true"}):
        configure_logging()

        # Define a custom level
        CUSTOM_LEVEL = 25
        logging.addLevelName(CUSTOM_LEVEL, "CUSTOM")

        # Log with custom level
        logging.log(CUSTOM_LEVEL, "Custom level message")

        out, _ = capture_logs.readouterr()
        assert out

        found = False
        for line in out.strip().split("\n"):
            if "Custom level message" in line:
                try:
                    log_entry = json.loads(line)
                    record = log_entry["record"]
                    assert record["message"] == "Custom level message"
                    # Loguru might map it to "Level 25" or similar if name not found in its registry
                    # In InterceptHandler, if logger.level(name) fails (ValueError), it uses str(levelno)
                    assert record["level"]["name"] == "Level 25"
                    found = True
                except (json.JSONDecodeError, KeyError):
                    pass
        assert found, "Custom level message not intercepted correctly"


def test_success_log_level_fallback() -> None:
    """Test that non-standard log level (SUCCESS) falls back to INFO for root logger."""
    with patch.dict(os.environ, {"COREASON_LOG_LEVEL": "SUCCESS"}):
        configure_logging()
        # Loguru accepts SUCCESS (25), but standard logging doesn't know it.
        # So logging.getLevelName("SUCCESS") returns string "Level SUCCESS" (or similar)
        # So it falls to else block -> logging.INFO
        assert logging.getLogger().level == logging.INFO


def test_logging_permission_error() -> None:
    """Test that PermissionError during log directory creation or file adding is ignored."""
    with (
        patch("pathlib.Path.exists", return_value=False),
        patch("pathlib.Path.mkdir", side_effect=PermissionError("Mock perm error")),
    ):
        # This should not raise exception
        configure_logging()

    # Test logger.add failure for file
    with patch("coreason_identity.utils.logger.logger.add") as mock_add:
        # First call is console, succeed. Second call is file, fail.
        # However, logger.add is called multiple times.
        # We can't easily side_effect based on args with simple Mock side_effect list if logic is complex
        # But we can assume call order.

        # Actually, let's just mock logger.add to raise error when called with filename
        def side_effect(*args: Any, **_kwargs: Any) -> int:
            if args and isinstance(args[0], str) and "app.log" in args[0]:
                raise PermissionError("File write error")
            return 1

        mock_add.side_effect = side_effect

        # This should not raise
        configure_logging()
