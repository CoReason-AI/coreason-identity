# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

from unittest.mock import Mock, patch

import pytest

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.manager import IdentityManagerSync


def test_import_old_class_fails() -> None:
    """Verify that IdentityManager is no longer importable from coreason_identity.manager."""
    with pytest.raises(ImportError):
        from coreason_identity.manager import IdentityManager  # type: ignore[attr-defined] # noqa: F401


def test_import_old_class_from_package_fails() -> None:
    """Verify that IdentityManager is no longer importable from coreason_identity package."""
    with pytest.raises(ImportError):
        from coreason_identity import IdentityManager  # type: ignore[attr-defined] # noqa: F401


def test_init_with_invalid_config_type() -> None:
    """Verify that IdentityManagerSync fails immediately if passed None or invalid config."""
    # Since type hints are checked statically, at runtime passing None might fail differently
    # depending on implementation details. We expect it to fail inside IdentityManagerAsync init
    # or earlier.

    # We'll just check it raises TypeError or AttributeError when accessing config fields
    with pytest.raises((AttributeError, TypeError)):
        IdentityManagerSync(None)  # type: ignore[arg-type]

    with pytest.raises((AttributeError, TypeError)):
        IdentityManagerSync("invalid-string-config")  # type: ignore[arg-type]


def test_context_manager_cleanup_idempotency() -> None:
    """Verify that __exit__ can be called multiple times without error (though unusual)."""
    config = CoreasonIdentityConfig(pii_salt="test-salt", domain="example.com", audience="aud", client_id="cid")

    with patch("coreason_identity.manager.IdentityManagerAsync") as MockAsync:
        mock_instance = MockAsync.return_value
        # Mock __aexit__ to be awaitable
        mock_instance.__aexit__ = Mock(return_value=None)
        # But wait, anyio.run(func, ...) calls func(). If func is async, it returns a coroutine.
        # So we need a coroutine function or something that returns a coroutine.

        async def mock_aexit(*args: object, **kwargs: object) -> None:
            pass

        mock_instance.__aexit__ = mock_aexit

        manager = IdentityManagerSync(config)

        # 1. Normal usage
        with manager:
            pass

        # 2. Manual call to exit
        manager.__exit__(None, None, None)

        # Should not raise
