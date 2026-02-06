import os
import sys
from collections.abc import Generator
from unittest.mock import patch

import pytest
from loguru import logger

from coreason_identity.utils.logger import configure_logging


@pytest.fixture
def clean_logger() -> Generator[None, None, None]:
    """Ensure logger is reset before and after tests."""
    logger.remove()
    yield
    logger.remove()


@pytest.mark.usefixtures("clean_logger")
def test_reconfiguration_toggling(capsys: pytest.CaptureFixture[str]) -> None:
    """
    Edge Case: Test toggling between JSON and Text logging via env vars.
    Verify that sinks are correctly replaced.
    """
    # 1. Test Text Logging (Default)
    with patch.dict(os.environ, {"COREASON_LOG_JSON": "false"}):
        configure_logging()
        logger.info("Text Log")

        captured = capsys.readouterr()
        assert "Text Log" in captured.err
        assert "{" not in captured.err  # Simple check for non-JSON

    # 2. Test JSON Logging
    with patch.dict(os.environ, {"COREASON_LOG_JSON": "true"}):
        # configure_logging should remove previous sinks and add new one
        configure_logging()
        logger.info("JSON Log")

        captured = capsys.readouterr()
        # JSON goes to stdout in our config
        # Loguru's serialized output structure contains "text" and "record" fields
        # but exact string matching can be brittle. We check for JSON structure.
        assert '"text":' in captured.out
        assert "JSON Log" in captured.out
        assert not captured.err  # Should be empty for JSON mode


@pytest.mark.usefixtures("clean_logger")
def test_multiple_configure_calls() -> None:
    """
    Edge Case: Verify that calling configure_logging multiple times
    does not duplicate handlers or crash.
    """
    configure_logging()
    handler_count_1 = len(logger._core.handlers)  # type: ignore

    configure_logging()
    handler_count_2 = len(logger._core.handlers)  # type: ignore

    # It should remain constant (1 sink) because configure_logging calls logger.configure(handlers=[])
    assert handler_count_1 == handler_count_2


@pytest.mark.usefixtures("clean_logger")
def test_stderr_replacement() -> None:
    """
    Edge Case: Verify behavior when sys.stderr is monkeypatched (e.g. by other libs).
    """
    original_stderr = sys.stderr
    try:
        # Mock stderr with a dummy object that has a write method
        class DummyStderr:
            def __init__(self) -> None:
                self.buffer: list[str] = []

            def write(self, msg: str) -> None:
                self.buffer.append(msg)

            def flush(self) -> None:
                pass

        dummy = DummyStderr()
        sys.stderr = dummy

        # Re-configure should pick up the new sys.stderr
        configure_logging()
        logger.info("Message to dummy stderr")

        # Loguru uses sys.stderr reference captured at sink addition.
        # configure_logging re-adds the sink, so it should use our dummy.
        # However, loguru writes might be async/buffered.

        # Wait for loguru to propagate
        logger.complete()

        assert any("Message to dummy stderr" in msg for msg in dummy.buffer)

    finally:
        sys.stderr = original_stderr
