import json
import os
import threading
from unittest.mock import patch

import pytest
from loguru import logger

from coreason_identity.utils.logger import configure_logging


def test_json_toggle(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify COREASON_LOG_JSON=true switches to stdout and uses JSON."""
    with patch.dict(os.environ, {"COREASON_LOG_JSON": "true", "COREASON_LOG_LEVEL": "INFO"}):
        configure_logging()
        logger.info("JSON Message")

        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out.strip() != ""

        # Verify valid JSON and content
        try:
            log_record = json.loads(captured.out)
            assert log_record["record"]["message"] == "JSON Message"
            assert log_record["record"]["level"]["name"] == "INFO"
        except json.JSONDecodeError:
            pytest.fail("Output was not valid JSON")


def test_invalid_log_level(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify invalid log level defaults to INFO."""
    with patch.dict(os.environ, {"COREASON_LOG_LEVEL": "INVALID_LEVEL_XYZ"}):
        configure_logging()
        logger.info("Info message")
        logger.debug("Debug message")

        captured = capsys.readouterr()
        assert "Info message" in captured.err
        # Default is INFO, so debug should be suppressed
        assert "Debug message" not in captured.err


def test_reconfiguration_resilience(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify calling configure_logging multiple times doesn't duplicate logs."""
    configure_logging()
    configure_logging()
    configure_logging()

    logger.info("Single message")

    captured = capsys.readouterr()
    # Should only appear once
    assert captured.err.count("Single message") == 1


def test_concurrency_stress() -> None:
    """Verify logging is thread-safe under load."""
    configure_logging()

    def log_worker() -> None:
        for i in range(100):
            logger.info(f"Worker thread {threading.get_ident()} iteration {i}")

    threads = []
    for _ in range(10):
        t = threading.Thread(target=log_worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # If we reached here without a crash/exception, it's a pass.
    # Loguru is thread-safe by default.
