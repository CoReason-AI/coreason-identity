# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import concurrent.futures
import time
from unittest.mock import AsyncMock, patch

import pytest

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.manager import IdentityManagerSync
from coreason_identity.models import UserContext


@pytest.fixture
def mock_identity_manager_sync() -> IdentityManagerSync:
    config = CoreasonIdentityConfig(
        pii_salt="test-salt", domain="test.auth0.com", audience="test-audience", client_id="test-client-id"
    )
    with patch("coreason_identity.manager.IdentityManagerAsync") as MockAsync:
        mock_instance = MockAsync.return_value

        # Setup mocks for methods
        mock_instance.validate_token = AsyncMock(return_value=UserContext(user_id="user123", email="test@example.com"))
        mock_instance.start_device_login = AsyncMock()
        mock_instance.await_device_token = AsyncMock()
        mock_instance.__aexit__ = AsyncMock()

        return IdentityManagerSync(config)


def test_concurrent_usage_in_threads(mock_identity_manager_sync: IdentityManagerSync) -> None:
    """
    Verify that IdentityManagerSync can be used concurrently in multiple threads.
    This simulates usage in a threaded web server (e.g. Flask/gunicorn).

    Each thread calls validate_token, which calls anyio.run(), creating a new loop each time.
    """

    def worker(token_suffix: str) -> str:
        # Simulate some work
        time.sleep(0.01)
        user = mock_identity_manager_sync.validate_token(f"Bearer token-{token_suffix}")
        return user.user_id

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(worker, str(i)) for i in range(10)]
        results = [f.result() for f in futures]

    assert len(results) == 10
    assert all(uid == "user123" for uid in results)

    # Check calls
    assert mock_identity_manager_sync._async.validate_token.call_count == 10  # type: ignore[attr-defined]


def test_reentrant_context_manager_usage(mock_identity_manager_sync: IdentityManagerSync) -> None:
    """
    Verify that the context manager can be entered and exited multiple times.
    This is redundant with edge cases but tests the flow explicitly.
    """
    # First entry
    with mock_identity_manager_sync:
        mock_identity_manager_sync.validate_token("Bearer token1")

    # Second entry (should be fine, as it just delegates to async manager which handles resources)
    with mock_identity_manager_sync:
        mock_identity_manager_sync.validate_token("Bearer token2")

    assert mock_identity_manager_sync._async.__aexit__.call_count == 2  # type: ignore[attr-defined]


def test_exception_propagation_from_async(mock_identity_manager_sync: IdentityManagerSync) -> None:
    """
    Verify that exceptions raised in the async layer are correctly propagated
    up through the sync facade.
    """
    mock_identity_manager_sync._async.validate_token.side_effect = ValueError("Async error")  # type: ignore[attr-defined]

    with pytest.raises(ValueError, match="Async error"):
        mock_identity_manager_sync.validate_token("Bearer fail")


def test_nested_sync_calls_via_callbacks_simulated(mock_identity_manager_sync: IdentityManagerSync) -> None:
    """
    Simulate a scenario where a sync function calls another sync function that uses the manager.
    Just to ensure stack depth or simple re-entrancy isn't an issue for anyio.run
    (which creates new loops, so it shouldn't be unless nested within an async loop).
    """

    def inner_function() -> str:
        user = mock_identity_manager_sync.validate_token("Bearer inner")
        return user.user_id

    def outer_function() -> str:
        return inner_function()

    assert outer_function() == "user123"
    assert mock_identity_manager_sync._async.validate_token.call_count == 1  # type: ignore[attr-defined]
