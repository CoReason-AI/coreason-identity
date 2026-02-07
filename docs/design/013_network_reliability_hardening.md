# Network Reliability Hardening

## 1. Overview

`coreason-identity` now enforces strict network reliability constraints to prevent thread exhaustion, resource starvation, and accidental production misconfigurations.

This design document outlines the implementation of:
1.  **Mandatory HTTP Timeouts:** Preventing infinite blocking on network I/O.
2.  **HTTPS Enforcement:** Preventing insecure communication with Identity Providers (IdPs).

## 2. Mandatory HTTP Timeouts

### The Problem
The default timeout for `httpx` (and many HTTP libraries) is often too lenient (e.g., 5 seconds or more, sometimes infinite for read operations). In high-throughput microservices, a slow IdP or network partition can cause threads to block indefinitely, leading to pool exhaustion and cascading failures.

### The Solution
We have removed "magic defaults." The consumer of `coreason-identity` **MUST** explicitly define their timeout budget. This forces a conscious decision about the acceptable latency for authentication operations.

*   **Implementation:**
    *   `CoreasonIdentityConfig` now includes a mandatory `http_timeout: float` field.
    *   `IdentityManagerAsync` initializes `httpx.AsyncClient` with this configured timeout.
    *   There is no default value; the application will fail to start if this is not provided.

### Testing Strategy
*   Verify that `CoreasonIdentityConfig` raises a `ValidationError` if `http_timeout` is missing.
*   Verify that `IdentityManagerAsync` correctly passes the timeout to the underlying HTTP client.
*   Verify that tests use a standard timeout (e.g., 5.0s) via `tests/conftest.py`.

## 3. HTTPS Enforcement

### The Problem
Allowing `http://` URLs for Identity Providers facilitates accidental production misconfigurations where sensitive tokens are transmitted in plaintext.

### The Solution
We enforce HTTPS for all IdP communications by default. This is checked at the configuration level.

*   **Implementation:**
    *   `CoreasonIdentityConfig.issuer` validator checks the URL scheme.
    *   If the scheme is `http`, it raises a `ValueError` unless the `unsafe_local_dev` flag is explicitly set to `True`.
    *   The `unsafe_local_dev` flag defaults to `False`.

### Local Development
For local testing (e.g., against a local Keycloak instance or mock server), developers must explicitly opt-in to insecurity:

```python
config = CoreasonIdentityConfig(
    domain="localhost:8080",
    audience="my-app",
    http_timeout=5.0,
    unsafe_local_dev=True  # Explicitly allow HTTP
)
```

## 4. Integration with SSRF Protection

This feature complements the existing DNS-based SSRF protection (`docs/design/005_ssrf_protection.md`).

*   **SSRF Protection:** Validates the *destination IP address* (preventing access to internal networks). controlled by `COREASON_DEV_UNSAFE_MODE`.
*   **HTTPS Enforcement:** Validates the *protocol* (preventing plaintext communication). controlled by `unsafe_local_dev` (config field).

Both protections are active by default and require separate explicit bypasses for local development.
