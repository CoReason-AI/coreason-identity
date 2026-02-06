# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import AsyncMock, Mock, MagicMock

import anyio
import httpx
import pytest

from coreason_identity.oidc_provider import OIDCProvider


@pytest.fixture
def mock_client() -> AsyncMock:
    client = AsyncMock(spec=httpx.AsyncClient)
    # Setup default response for get_jwks to avoid actual network calls or crashes
    client.get.return_value = Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks", "keys": []})
    return client


def test_sync_init_async_run(mock_client: AsyncMock) -> None:
    """
    Verifies that OIDCProvider can be instantiated in a synchronous context
    and then successfully used inside an anyio.run() loop.
    """
    # 1. Instantiate in Sync Context
    provider = OIDCProvider("https://idp", mock_client)

    # 2. Define async function that uses the provider
    async def run_check() -> None:
        mock_client.get.side_effect = [
            Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
            Mock(status_code=200, json=lambda: {"keys": []}),
        ]
        await provider.get_jwks()

    # 3. Run inside a NEW loop
    anyio.run(run_check)


def test_provider_reuse_across_loops(mock_client: AsyncMock) -> None:
    """
    Verifies that OIDCProvider survives being used in two sequential anyio.run calls.
    This simulates the Sync Facade usage where every API call creates a fresh loop.
    """
    provider = OIDCProvider("https://idp", mock_client)

    async def run_check() -> None:
        mock_client.get.side_effect = [
            Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
            Mock(status_code=200, json=lambda: {"keys": []}),
        ]
        await provider.get_jwks(force_refresh=True)

    # Run 1
    anyio.run(run_check)

    # Run 2
    # Even if this passes natively in some envs, we want to ensure it works reliable.
    anyio.run(run_check)


def test_concurrent_access_in_loop(mock_client: AsyncMock) -> None:
    """
    Verifies multiple concurrent calls in the same loop work correctly.
    """
    provider = OIDCProvider("https://idp", mock_client)

    async def worker() -> None:
        await provider.get_jwks(force_refresh=True)

    async def run_concurrent() -> None:
        # We simulate that only one fetch happens (mock side effect has finite items)
        # If lock fails, we might get errors or extra calls.
        mock_client.get.side_effect = [
            Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
            Mock(status_code=200, json=lambda: {"keys": ["key1"]}),
        ]
        # Any subsequent calls would fail StopIteration if called, or return default

        async with anyio.create_task_group() as tg:
            tg.start_soon(worker)
            tg.start_soon(worker)
            tg.start_soon(worker)

    anyio.run(run_concurrent)


def test_lock_recreation_on_loop_error(mock_client: AsyncMock) -> None:
    """
    Verifies that if acquiring the lock raises a RuntimeError (due to loop mismatch),
    the provider automatically recreates the lock and tries again.
    """
    provider = OIDCProvider("https://idp", mock_client)

    # Mock the lock to raise RuntimeError on enter
    # We can't easily mock anyio.Lock's __aenter__ directly on the instance before it exists.
    # So we let it create one, then monkeypatch it.

    async def scenario() -> None:
        # 1. Initialize lock
        if provider._lock is None:
            provider._lock = anyio.Lock()

        # 2. Corrupt the lock to simulate "attached to different loop"
        # We wrap the lock to raise error on acquire
        original_lock = provider._lock

        # Create a mock that raises RuntimeError on __aenter__ ONCE, then works
        flaky_lock = MagicMock()

        # __aenter__ is async, so it returns an awaitable.
        async def fail_then_succeed(*args, **kwargs):
            raise RuntimeError("Task <...> got Future <...> attached to a different loop")

        flaky_lock.__aenter__.side_effect = fail_then_succeed

        # Replace the lock
        provider._lock = flaky_lock # type: ignore

        # 3. Call get_jwks
        # We expect it to catch the error, create a NEW lock (real anyio.Lock), and succeed.
        # We need mock_client to respond
        mock_client.get.side_effect = [
            Mock(status_code=200, json=lambda: {"jwks_uri": "https://idp/jwks"}),
            Mock(status_code=200, json=lambda: {"keys": ["recovered"]}),
        ]

        jwks = await provider.get_jwks(force_refresh=True)
        assert jwks == {"keys": ["recovered"]}

        # 4. Verify lock was replaced
        assert provider._lock is not flaky_lock
        assert isinstance(provider._lock, anyio.Lock)

    # This test will FAIL until we implement the fix
    try:
        anyio.run(scenario)
    except RuntimeError as e:
        pytest.fail(f"Did not handle RuntimeError: {e}")
