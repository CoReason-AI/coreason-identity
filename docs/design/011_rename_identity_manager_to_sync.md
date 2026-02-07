# Design 011: Rename `IdentityManager` to `IdentityManagerSync`

**Status**: Implemented
**Date**: 2026-02-07

## Context

The `coreason-identity` library originally provided two main entry points:
1.  `IdentityManagerAsync`: The core, asynchronous implementation.
2.  `IdentityManager`: A synchronous facade using `anyio.run()`.

The name `IdentityManager` was ambiguous. In modern Python development, libraries are often expected to be async-first or at least explicit about their blocking nature. The original name implied that it was the "standard" or "default" way to use the library, potentially leading developers to use it inadvertently in asynchronous contexts (e.g., within a FastAPI endpoint).

Calling `anyio.run()` from within an already running event loop (which happens if `IdentityManager` is used inside an async function) typically results in a `RuntimeError` or nested loop issues depending on the backend.

## Decision

We have renamed `IdentityManager` to `IdentityManagerSync`. This is a **breaking change** intended to:

1.  **Loudly Signal Blocking IO**: The suffix `Sync` makes it immediately clear that the class performs blocking operations.
2.  **Prevent Accidental Misuse**: Developers must consciously choose the synchronous implementation. If they are in an async environment, the name serves as a warning.
3.  **Promote Async-First**: The absence of a suffix-less "default" encourages developers to look at available options and choose `IdentityManagerAsync` for modern applications.

## Implementation Details

*   **Renaming**: `class IdentityManager` -> `class IdentityManagerSync` in `src/coreason_identity/manager.py`.
*   **Exports**: Updated `src/coreason_identity/__init__.py` to export `IdentityManagerSync`.
*   **Documentation**: All references to the synchronous facade in documentation and docstrings have been updated.
*   **Testing**: The test suite has been updated to use the new class name. New tests have been added to verify edge cases and complex usage patterns of the synchronous facade.

## Migration Guide

### Old Code

```python
from coreason_identity import IdentityManager, CoreasonIdentityConfig

config = CoreasonIdentityConfig(...)
manager = IdentityManager(config)

user = manager.validate_token("token")
```

### New Code

```python
from coreason_identity import IdentityManagerSync, CoreasonIdentityConfig

config = CoreasonIdentityConfig(...)
# Explicitly use the Sync facade
manager = IdentityManagerSync(config)

user = manager.validate_token("token")
```

If you are using `async/await` (e.g., FastAPI, Quart), you should use `IdentityManagerAsync` instead:

```python
from coreason_identity import IdentityManagerAsync

async with IdentityManagerAsync(config) as manager:
    user = await manager.validate_token("token")
```
