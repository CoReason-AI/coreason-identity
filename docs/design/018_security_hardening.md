# 018: Security Hardening (SOTA Implementation)

## Overview

This document details the security hardening measures implemented in version 0.8.0 to address critical vulnerabilities identified in the security audit. The remediation strategy follows a "State-of-the-Art" (SOTA) approach, prioritizing structural fixes over ad-hoc patches.

## 1. SSRF & DoS Protection (The "Safe Transport" Pattern)

### Vulnerability
Standard HTTP clients (like `httpx`) resolve DNS and connect blindly. This allows attackers to use DNS Rebinding or specific IP ranges (localhost, private networks) to access internal infrastructure (SSRF). Additionally, unbounded reads of HTTP responses can lead to Memory Exhaustion (DoS).

### Remediation
We implemented a custom `SafeAsyncTransport` in `src/coreason_identity/transport.py`.

*   **DNS Resolution:** We perform explicit DNS resolution before connection.
*   **IP Filtering:** Resolved IPs are checked against a blocklist:
    *   Loopback (`127.0.0.0/8`)
    *   Private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
    *   Link-Local (`169.254.0.0/16`)
*   **Safe Connection:** If valid, the connection is made directly to the IP address. The original `Host` header and SNI are preserved to ensure correct routing and SSL validation.
*   **Bounded Reads:** The `safe_json_fetch` utility enforces strict limits on response size (default 1MB) by checking `Content-Length` and streaming bytes with a running counter.

## 2. PII Leakage Prevention (Structured Sanitization)

### Vulnerability
Exceptions, particularly `pydantic.ValidationError`, often contain the raw input data in their error messages or attributes. Logging these exceptions directly leaks Personally Identifiable Information (PII) into log aggregation systems.

### Remediation
We refactored `IdentityMapper` in `src/coreason_identity/identity_mapper.py` to implement **Context-Aware Error Formatting**.

*   **Sanitization:** When a validation error occurs, we iterate through the error details.
*   **Redaction:** We strictly extract only the `loc` (field name) and `msg` (error type). The `input` and `ctx` fields, which hold the raw data, are explicitly excluded.
*   **Safe Logging:** Only the sanitized list of errors is logged or raised in `CoreasonIdentityError`.

## 3. Replay Protection (JTI Caching)

### Vulnerability
JWTs are stateless. Without a mechanism to track used tokens, a valid token intercepted by an attacker can be replayed multiple times within its validity window.

### Remediation
We introduced a `TokenCacheProtocol` abstraction in `src/coreason_identity/validator.py`.

*   **Interface:** `is_jti_used(jti: str, exp: int) -> bool`
*   **Default Implementation:** `MemoryTokenCache` (in-memory, strictly for single-instance deployments).
*   **Extensibility:** Users can implement distributed caches (Redis/Memcached) for multi-instance deployments.
*   **Enforcement:** `TokenValidator` checks every token's `jti` claim against the cache. If found, `TokenReplayError` is raised.

## 4. Async Context Propagation

### Vulnerability
In asynchronous environments (like FastAPI), global state is unsafe. Without proper context management, user identity from one request could leak into another concurrent request.

### Remediation
We implemented `src/coreason_identity/async_context.py` using Python's native `contextvars`.

*   **Isolation:** `_current_user` is a `ContextVar`, ensuring that the user context is thread-safe and task-local.
*   **API:** `get_current_user()` and `set_current_user()` provide a safe interface for accessing the identity of the current request execution context.

## Usage Updates

### Token Validator with Cache

```python
from coreason_identity.validator import TokenValidator, MemoryTokenCache

# Default uses MemoryTokenCache
validator = TokenValidator(..., cache=MemoryTokenCache())

# Custom Redis Cache (Example)
class RedisTokenCache:
    def is_jti_used(self, jti: str, exp: int) -> bool:
        # Check Redis...
        return False

validator = TokenValidator(..., cache=RedisTokenCache())
```

### Async Context

```python
from coreason_identity.async_context import set_current_user, clear_current_user

# Middleware
async def auth_middleware(request, call_next):
    user = validate_token(request.headers["Authorization"])
    set_current_user(user)
    try:
        response = await call_next(request)
    finally:
        clear_current_user()
```
