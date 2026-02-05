# Design 006: JWKS Refresh Rate Limiting (DoS Protection)

## Context

The `OIDCProvider` fetches JSON Web Key Sets (JWKS) from an Identity Provider (IdP) to validate JWT signatures. The `TokenValidator` employs a "fail-closed" retry mechanism: if a token signature is invalid (`BadSignatureError`), it triggers a forced JWKS refresh (`get_jwks(force_refresh=True)`) and retries validation once.

## Vulnerability (Finding #2)

An attacker can exploit this retry mechanism by flooding the application with tokens bearing invalid signatures. Each request triggers a `force_refresh=True` call. Without rate limiting, this causes the application to hammer the IdP's JWKS endpoint, potentially leading to:
1.  **Denial of Service (DoS)** of the IdP (hitting rate limits).
2.  **Self-DoS** (application threads blocked waiting for IdP).
3.  **Cost spikes** (if IdP charges per request).

## Solution: Mandatory Cooldown

We implement a mandatory cooldown period (rate limiter) for forced refreshes within the `OIDCProvider`.

### Mechanism

1.  **Configuration:** A new parameter `refresh_cooldown` (float, default 30.0s) is added to `OIDCProvider`.
2.  **State Tracking:** We track `_last_refresh_attempt` timestamp.
3.  **Logic:**
    *   When `get_jwks(force_refresh=True)` is called:
        *   Check `current_time - _last_refresh_attempt < refresh_cooldown`.
        *   If within cooldown AND cache exists:
            *   Log a warning ("JWKS refresh rate limit hit").
            *   Return the **cached** keys immediately (Fail-Cached).
        *   If outside cooldown:
            *   Update `_last_refresh_attempt = current_time`.
            *   Proceed to fetch from IdP.
            *   On success, update `_last_update` and `_jwks_cache`.

### Distinction: `cache_ttl` vs `refresh_cooldown`

*   `cache_ttl` (default 1h): How long a successful fetch is considered "fresh" for *normal* operations. Used when `force_refresh=False`.
*   `refresh_cooldown` (default 30s): The minimum time *between* network requests, specifically guarding `force_refresh=True`.

### Edge Cases & Red Team Analysis

*   **IdP Outage:** If the IdP returns 500s, `_last_refresh_attempt` is still updated. This prevents the application from hammering a struggling IdP. The application will retry only once every 30s.
*   **Startup:** If `_jwks_cache` is `None` (application just started), the cooldown is bypassed to ensure the app can function.
*   **Log Flooding:** Continuous attacks could spam logs. (Future improvement: Log throttling).

## API Changes

```python
class OIDCProvider:
    def __init__(self, ..., refresh_cooldown: float = 30.0):
        ...
```
