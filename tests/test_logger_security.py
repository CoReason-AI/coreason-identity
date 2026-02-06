import shutil
from collections.abc import Generator
from pathlib import Path

import pytest

from coreason_identity.utils.logger import configure_logging, logger


@pytest.fixture(autouse=True)
def cleanup_logs() -> Generator[None, None, None]:
    """Ensure logs directory is clean before and after tests."""
    log_path = Path("logs")
    if log_path.exists():
        shutil.rmtree(log_path)
    yield
    if log_path.exists():
        shutil.rmtree(log_path)


def test_no_file_creation() -> None:
    """
    Test Case 1: Verify that logging does not create a file on disk.
    Finding #7 Mitigation.
    """
    # Re-configure logging to trigger the file creation logic (if present)
    configure_logging()

    # Force a log emission
    logger.info("Testing file creation")

    # Wait for async logging to complete
    logger.complete()

    # Assert that the file logs/app.log does not exist
    log_file = Path("logs/app.log")

    assert not log_file.exists(), "logs/app.log should not be created"


def test_stderr_output(capsys: pytest.CaptureFixture[str]) -> None:
    """
    Test Case 2: Verify that logging outputs to stderr.
    Finding #7 Mitigation.
    """
    # Ensure the logger is configured with default settings (which should be stderr)
    configure_logging()

    msg = "This should go to stderr"
    logger.warning(msg)

    # Loguru writes to stderr synchronously by default unless enqueue=True
    captured = capsys.readouterr()
    assert msg in captured.err
