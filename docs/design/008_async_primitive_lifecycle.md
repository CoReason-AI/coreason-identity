# Async Primitive Lifecycle and Sync Facade

## The Problem

`coreason-identity` uses an "Async-Native with Sync Facade" architecture. This means the core logic (`IdentityManagerAsync`) uses `async/await` and libraries like `httpx` and `anyio`. However, to support synchronous applications (e.g., standard Flask or Django apps), we provide a synchronous facade (`IdentityManagerSync`) that wraps these calls using `anyio.run()`.

The `IdentityManagerSync` facade instantiates the async components (`IdentityManagerAsync`, `OIDCProvider`) once in its `__init__`. However, every method call (e.g., `validate_token`) invokes `anyio.run()`, which typically creates a **new event loop**.

Stateful objects like `anyio.Lock` are often bound to the event loop where they are created or first used. If an `OIDCProvider` instance persists across multiple `anyio.run()` calls (i.e., multiple ephemeral loops), its internal lock becomes stale or bound to a closed loop. Attempting to use this lock in a new loop raises a `RuntimeError` (e.g., "Task ... attached to a different loop").

## The Solution

To ensure robustness, components that hold async primitives must handle this lifecycle mismatch.

### 1. Lazy Initialization

Primitives should not be initialized in `__init__` (which runs synchronously, often with no loop). Instead, they should be initialized lazily inside the async method that uses them.

```python
# Bad
def __init__(self):
    self._lock = anyio.Lock() # Might bind to wrong loop or no loop

# Good
def __init__(self):
    self._lock = None

async def critical_section(self):
    if self._lock is None:
        self._lock = anyio.Lock() # Binds to current loop
```

### 2. Loop Mismatch Recovery

If an object is reused across different loops (as `OIDCProvider` is), a lazily-initialized lock from "Loop A" might be encountered when running in "Loop B".

We implement a "EAFP" (Easier to Ask for Forgiveness than Permission) strategy:

1.  Attempt to acquire the lock.
2.  Catch `RuntimeError`.
3.  Check if the error indicates a loop mismatch (e.g., "attached to a different loop").
4.  If so, discard the old lock, create a new one for the current loop, and retry.

```python
try:
    async with self._lock:
        await do_work()
except RuntimeError as e:
    if "attached to a different loop" in str(e):
        logger.warning("Recreating lock due to loop mismatch")
        self._lock = anyio.Lock()
        async with self._lock:
            await do_work()
    else:
        raise
```

## Applicability

This pattern applies to any component that:
1.  Is long-lived (persists across requests).
2.  Holds `anyio` synchronization primitives (`Lock`, `Event`, `Semaphore`).
3.  Is accessed via a Sync Facade that uses `anyio.run()` per call.

Currently, this is primarily relevant for `OIDCProvider` (which caches JWKS and needs locking for cache updates).
