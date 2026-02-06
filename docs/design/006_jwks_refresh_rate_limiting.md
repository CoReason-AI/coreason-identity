# 006: JWKS Refresh Rate Limiting & Async Safety

## Status
Accepted

## Context
The `OIDCProvider` component is responsible for fetching and caching JSON Web Key Sets (JWKS) from an Identity Provider (IdP). It supports a `force_refresh=True` parameter to allow callers to bypass the cache when a token validation fails (potentially due to key rotation).

### Problems Identified
1.  **Denial of Service (DoS) Risk:** An attacker could send a flood of invalid tokens with a `kid` (Key ID) not in the current cache. This would trigger the validation logic to call `get_jwks(force_refresh=True)` repeatedly. Without rate limiting, this would cause the application to flood the IdP with requests, leading to rate limiting by the IdP (429 Too Many Requests) or resource exhaustion.
2.  **Async Runtime Error:** The `anyio.Lock` used for concurrency control was initialized in the synchronous `__init__` method. When the `OIDCProvider` was used within an `anyio.run()` context (which creates a new event loop), the lock would be bound to a different (or non-existent) loop, causing a `RuntimeError: Task ... got Future ... attached to a different loop`.

## Decision

### 1. JWKS Refresh Rate Limiting
We implemented a mandatory cooldown period for forced refreshes.

*   **Mechanism:** A new parameter `refresh_cooldown` (default: 30.0 seconds) was added.
*   **Logic:** inside `get_jwks(force_refresh=True)`:
    1.  Check if a valid cache exists (`_jwks_cache` is not None).
    2.  Calculate time since last successful update (`time.time() - self._last_update`).
    3.  If the elapsed time is less than `refresh_cooldown`, **ignore the forced refresh request**.
    4.  Log a warning ("JWKS refresh cooldown active...").
    5.  Return the *currently cached keys*.

*   **Rationale:** This ensures that even under attack, the application will only contact the IdP once every 30 seconds (or configured interval). Legitimate users might see a delay in key rotation propagation of up to 30 seconds, which is an acceptable trade-off for stability.

### 2. Lazy Lock Initialization
We moved the initialization of `anyio.Lock` from `__init__` to `get_jwks`.

*   **Mechanism:** `self._lock` is initialized to `None`.
*   **Logic:** At the start of `get_jwks` (an `async` method), we check:
    ```python
    if self._lock is None:
        self._lock = anyio.Lock()
    ```
*   **Rationale:** This ensures that the `Lock` object is created within the running `anyio` event loop where it will be used, resolving the `RuntimeError`.

## Consequences

### Positive
*   **Resilience:** The system is protected against DoS attacks targeting the JWKS refresh mechanism.
*   **Stability:** The `OIDCProvider` can be safely used in various async contexts (e.g., inside `anyio.run` wrappers or direct async calls) without crashing.
*   **Observability:** Warning logs provide visibility into when the rate limiter is active.

### Negative
*   **Latency:** In the rare event of a legitimate key rotation, if a refresh was triggered immediately before the rotation, subsequent refreshes will be blocked for 30 seconds. This adds a potential 30s latency to accepting new keys.
