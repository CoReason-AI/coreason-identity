import threading
import time
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor

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
def test_concurrent_logging_and_reconfiguration() -> None:
    """
    Complex Case: Verify thread safety when logging heavily while re-configuring.
    This simulates a race condition where config changes during active use.
    """
    stop_event = threading.Event()

    def log_worker() -> None:
        while not stop_event.is_set():
            logger.info("Worker log")
            time.sleep(0.001)

    def config_worker() -> None:
        for _ in range(10):
            configure_logging()
            time.sleep(0.01)

    with ThreadPoolExecutor(max_workers=5) as executor:
        # Start logging threads
        futures = [executor.submit(log_worker) for _ in range(4)]

        # Start config thread
        config_future = executor.submit(config_worker)

        # Wait for config to finish
        config_future.result()

        stop_event.set()
        for f in futures:
            f.result()

    # If we reached here without a crash/deadlock, it's a pass.
    # Loguru is thread-safe, but our configure_logging replaces handlers.


@pytest.mark.usefixtures("clean_logger")
def test_stress_trace_injection() -> None:
    """
    Complex Case: Stress test the trace_id_injector patcher.
    Verify performance/stability under high load with OpenTelemetry hooks.
    """
    configure_logging()

    # We rely on the patcher installed by configure_logging

    start_time = time.time()
    iterations = 1000

    for i in range(iterations):
        logger.info(f"Stress message {i}")

    duration = time.time() - start_time

    # Simple perf sanity check (should be fast enough, < 1s for 1k logs)
    # This isn't a strict perf test, just verifying we didn't introduce massive overhead
    assert duration < 5.0
