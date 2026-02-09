# Security Audit Report: coreason-identity v0.8.0

## 1. Executive Summary
The `coreason-identity` library exhibits a "Zero Trust" philosophy only in its token validation logic, while completely abdicating network security to the underlying infrastructure. By removing `SafeHTTPTransport`, the library is now a wide-open proxy for SSRF attacks if deployed in standard environments. While it successfully mitigates algorithm confusion and enforces strict clock skew, the lack of replay protection (`jti` caching) and potential PII leaks in exception logging undermine its security posture. The library is "secure by configuration" but "insecure by default" regarding network boundaries and resource consumption.

## 2. Critical Vulnerabilities (CVSS 9.0+)

### **CV-1: Full SSRF Bypass via Infrastructure Delegation**
*   **Module:** `oidc_provider.py`, `device_flow_client.py`
*   **Description:** The library uses a standard `httpx.AsyncClient` without any IP filtering or DNS pinning. The `SafeHTTPTransport` mechanism was explicitly removed (as per `005_ssrf_protection.md`).
*   **Exploit:** An attacker who can influence the `discovery_url` (e.g., via environment injection or if the app allows dynamic IdP configuration) can force the server to request `http://169.254.169.254/latest/meta-data/` or scan internal ports (e.g., `http://localhost:6379`).
*   **Impact:** Full cloud account compromise (via metadata credentials) or access to internal services.

### **CV-2: Unbounded Memory Consumption (DoS)**
*   **Module:** `oidc_provider.py`, `device_flow_client.py`
*   **Description:** HTTP responses are parsed using `.json()` without checking `Content-Length` or streaming the response with a size limit.
*   **Exploit:** A malicious IdP (or a compromised DNS pointing to an attacker's server) can return a 50GB JSON stream.
*   **Impact:** Application crash (OOM Kill), Denial of Service.

## 3. High Risks (CVSS 7.0+)

### **HR-1: PII Leak in Exception Logging**
*   **Module:** `identity_mapper.py`
*   **Description:** The `IdentityMapper.map_claims` method catches `pydantic.ValidationError` and logs it using `logger.error`.
*   **Snippet:** `logger.error(f"UserContext validation failed due to invalid claims: {e}")`
*   **Exploit:** If a user provides a malformed email or group that triggers a validation error, the raw value is written to the logs.
*   **Impact:** PII leakage in logs, violating privacy requirements.

### **HR-2: Lack of Replay Protection**
*   **Module:** `validator.py`
*   **Description:** The `TokenValidator` checks `exp` (expiration) but ignores the `jti` (JWT ID) claim. It does not cache seen `jti` values.
*   **Exploit:** An attacker who intercepts a valid access token can replay it against the API multiple times within the validation window (determined by `exp` + 0s leeway).
*   **Impact:** Unauthorized actions, duplicate transaction processing.

### **HR-3: Missing Context Propagation**
*   **Module:** `async_context.py` (Missing)
*   **Description:** The requested `async_context.py` module is absent. The library does not provide a standard way to propagate `UserContext` across async tasks.
*   **Impact:** Developers may implement unsafe global state or thread-local storage, leading to "Identity Confusion" (leaking one user's context to another request).

## 4. Design vs. Code Gaps

*   **SSRF Protection:**
    *   **Doc:** "The strict runtime Server-Side Request Forgery (SSRF) protection ... has been REMOVED" (`005_ssrf_protection.md`).
    *   **Requirement:** User asked: "Does the code *strictly* block requests...?"
    *   **Finding:** No. The code explicitly fails this requirement based on the design decision to delegate trust.
*   **PII Redaction in Logs:**
    *   **Requirement:** "Review the `PIIRedactingFormatter`".
    *   **Finding:** `PIIRedactingFormatter` is missing. `src/coreason_identity/utils/logger.py` uses `loguru` with a basic `trace_id_injector` and no PII scrubbing logic.
*   **Strict Token Validation:**
    *   **Doc:** Claims strict validation.
    *   **Finding:** Mostly compliant (Algorithms, Leeway), but misses `jti` checks.

## 5. "Paranoid" Recommendations

1.  **Re-implement `SafeHTTPTransport`:** Do not trust the infrastructure. Inject a custom `httpx.Transport` that performs DNS resolution and checks IPs against a blocklist (RFC1918, Loopback, Link-Local) *before* establishing a connection.
2.  **Enforce Content Limits:** Wrap all `httpx` calls with a helper that streams the response and raises an exception if `Content-Length` > 1MB or if the stream exceeds 1MB.
3.  **Implement JTI Cache:** Add a `JtiCache` interface (with Redis/Memcached adapters) to `TokenValidator`. Store `jti` with a TTL equal to the token's remaining lifetime. Reject if present.
4.  **Sanitize Exception Logs:** Modify `IdentityMapper` to catch `ValidationError`, iterate over the errors, and log only the *field names* that failed, not the values.
5.  **Restore `async_context.py`:** Implement a `contextvars`-based `current_user` object to ensure safe concurrency.
