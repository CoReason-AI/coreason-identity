# Security Audit Report: coreason-identity

**Date:** 2025-05-28
**Auditor:** Jules (AI Security Engineer)
**Target:** `coreason-identity` package

This report details 10 prioritized security issues identified during a red team analysis of the `coreason-identity` codebase. The focus was on architectural vulnerabilities, protocol deviations, and implementation flaws.

## Prioritized Findings

| ID | Severity | Issue | Component |
|----|----------|-------|-----------|
| 1 | **Critical** | Blind SSRF via Unvalidated OIDC Discovery URL | `config.py` / `oidc_provider.py` |
| 2 | **High** | Denial of Service (DoS) via Unrestricted JWKS Refresh | `validator.py` / `oidc_provider.py` |
| 3 | **High** | Resource Exhaustion via Unbounded Device Flow Polling | `device_flow_client.py` |
| 4 | **Medium** | Weak PII Anonymization (Unsalted SHA-256) | `validator.py` |
| 5 | **Medium** | PII Leakage in OpenTelemetry Spans | `validator.py` |
| 6 | **Medium** | Implicit Issuer Trust (Trust-On-First-Use) | `validator.py` |
| 7 | **Medium** | Injection Risk via Unsanitized Project Context | `identity_mapper.py` |
| 8 | **Medium** | Missing Authorized Party (`azp`) Validation | `validator.py` |
| 9 | **Medium** | Information Leakage in Exception Messages | `exceptions.py` |
| 10 | **Low** | Lack of Explicit HTTP Client Timeouts | `manager.py` |

---

### 1. Blind SSRF via Unvalidated OIDC Discovery URL

**Severity:** Critical

**Description:**
The `IdentityManagerAsync` initializes the `OIDCProvider` using a `discovery_url` constructed from `config.domain`. While `config.py` ensures the domain is a valid hostname (stripping scheme/path), it does not validate the resolution of that hostname. A malicious actor with control over the environment variables (`COREASON_AUTH_DOMAIN`) could point the domain to an internal service (e.g., `169.254.169.254`, `localhost`, or an intranet service). The `OIDCProvider` then blindly makes a GET request to `https://<internal-ip>/.well-known/openid-configuration`. If the internal service returns JSON, the parser might process it. Even if it doesn't, this allows for internal port scanning or interacting with unauthenticated internal APIs (Blind SSRF).

**Conceptual Solution:**
Implement a strict **Allowlist** of permitted domains if the set of IdPs is known (e.g., only `*.coreason.com` or `*.auth0.com`). Alternatively, implement a **Denylist** for private IP ranges (RFC 1918, loopback, link-local) by resolving the DNS before making the request, or use a network proxy that enforces these rules. The `config.py` validator should reject domains that resolve to private IPs.

### 2. Denial of Service (DoS) via Unrestricted JWKS Refresh

**Severity:** High

**Description:**
In `TokenValidator.validate_token`, catching a `BadSignatureError` triggers `self.oidc_provider.get_jwks(force_refresh=True)`. This argument bypasses the cache in `OIDCProvider` and immediately executes a network request to the IdP. Although `OIDCProvider` uses a lock to serialize requests, it does not check if a refresh *just* happened. An attacker can send a flood of tokens with invalid signatures. Each request will acquire the lock (sequentially) and trigger a fresh HTTP request to the IdP, bypassing the `cache_ttl`. This can lead to resource exhaustion on the service (thread/connection pool starvation) or trigger rate limits at the IdP, effectively denying service to legitimate users.

**Conceptual Solution:**
Implement a **"Refresh Cooldown"** or **"Circuit Breaker"** in `OIDCProvider.get_jwks`. When `force_refresh=True` is requested, the provider should check `time.time() - self._last_update`. If the last update was very recent (e.g., < 10 seconds), it should return the cached value (or raise a `RateLimitError`) instead of fetching again, even if `force_refresh` is True.

### 3. Resource Exhaustion via Unbounded Device Flow Polling

**Severity:** High

**Description:**
The `DeviceFlowClient.poll_token` method relies entirely on the `expires_in` and `interval` values returned by the IdP to control its loop. It runs `while time.time() < end_time`. If a compromised or malicious IdP (or a Man-in-the-Middle) returns an extremely large `expires_in` (e.g., 10 years) and a tiny `interval` (e.g., 0.001s), the client will loop indefinitely and rapidly, consuming CPU and network resources.

**Conceptual Solution:**
Enforce **Upper Bounds** on `expires_in` (e.g., max 15 minutes) and **Lower Bounds** on `interval` (e.g., min 5 seconds) within the client logic. Ignore IdP values that violate these safety constraints to ensure the client remains well-behaved.

### 4. Weak PII Anonymization (Unsalted SHA-256)

**Severity:** Medium

**Description:**
The `TokenValidator` logs user activity by hashing the `sub` claim: `hashlib.sha256(str(user_sub).encode("utf-8")).hexdigest()`. This uses a standard, unsalted SHA-256 hash. Because the input space for `sub` is often low-entropy (e.g., integer IDs or short usernames), these hashes are vulnerable to rainbow table attacks or brute-force reversal. This compromises the privacy guarantees claimed by the "PII hashed" feature.

**Conceptual Solution:**
Use **HMAC-SHA256** with a high-entropy, secret **Salt** (configured via environment variables) instead of plain SHA-256. This ensures that the hashes cannot be reversed without access to the secret key.

### 5. PII Leakage in OpenTelemetry Spans

**Severity:** Medium

**Description:**
While the logs use hashed user IDs, the `TokenValidator` explicitly sets the raw `sub` claim on the OpenTelemetry span: `span.set_attribute("user.id", str(user_sub))`. If the `sub` claim contains PII (such as an email address, which is common in OIDC), this PII is transmitted in cleartext to the observability backend. This bypasses the redaction efforts applied to the logs and may violate privacy compliance requirements (GDPR/CCPA).

**Conceptual Solution:**
Apply the same **Hashing/Anonymization** logic (preferably the HMAC solution from Issue #4) to the span attribute `user.id` before setting it. Do not send raw PII to tracing systems.

### 6. Implicit Issuer Trust (Trust-On-First-Use)

**Severity:** Medium

**Description:**
By default, `TokenValidator` is initialized with `issuer=None`. It relies on `OIDCProvider.get_issuer()` which fetches the issuer from the `.well-known/openid-configuration` endpoint. This creates a "Trust-On-First-Use" (TOFU) scenario. If an attacker can spoof the DNS or hijack the connection to the discovery endpoint, they can serve a malicious config with an attacker-controlled `issuer` and `jwks_uri`. The validator will then validly verify tokens signed by the attacker.

**Conceptual Solution:**
Enforce **Strict Issuer Validation**. The expected `issuer` should be a mandatory configuration parameter in `CoreasonIdentityConfig`. The `TokenValidator` should verify that the `iss` claim in the token matches this hardcoded, trusted string, rather than trusting whatever the discovery endpoint claims the issuer is.

### 7. Injection Risk via Unsanitized Project Context

**Severity:** Medium

**Description:**
The `IdentityMapper` extracts the `project_context` from group names using the regex `r"^project:\s*(.*)"`. The `(.*)` group captures *any* characters until the end of the string. If a user can create a group named `project: <script>alert(1)</script>` or `project: ../../../etc/passwd`, this payload is extracted as-is and placed into the `UserContext`. If consuming applications use this value in HTML output (XSS) or file paths (Path Traversal) without further sanitization, it creates a vulnerability.

**Conceptual Solution:**
Refine the regex to allow only a **Safe Character Set** (e.g., `r"^project:\s*([a-zA-Z0-9_-]+)"`). Reject or sanitize any `project_context` values that contain special characters, whitespace, or control codes.

### 8. Missing Authorized Party (`azp`) Validation

**Severity:** Medium

**Description:**
The `TokenValidator` validates the `aud` (audience) claim, which ensures the token is meant for the API. However, it does not validate the `azp` (Authorized Party) claim. In OIDC, `azp` identifies the client that requested the token. Without checking `azp`, a token issued to a legitimate but untrusted client (Client B) for the same audience (API A) is accepted, even if only the trusted internal app (Client A) should be accessing the API. This is a form of the "Confused Deputy" problem.

**Conceptual Solution:**
If the API is intended to be accessed only by specific clients, verify the `azp` claim against a list of **Allowed Client IDs**. At a minimum, log the `azp` to allow for audit and anomaly detection.

### 9. Information Leakage in Exception Messages

**Severity:** Medium

**Description:**
The `CoreasonIdentityError` class and its usages frequently wrap underlying exceptions including their full string representation (e.g., `raise CoreasonIdentityError(f"Failed to fetch ...: {e}")`). If `e` is an `httpx.HTTPError`, it might contain the full URL (including query parameters), headers, or internal network details (IP addresses). Propagating these details up the stack can leak internal infrastructure information to the API caller or external logs.

**Conceptual Solution:**
**Sanitize Exception Messages**. Catch low-level exceptions and raise high-level errors with generic messages (e.g., "Upstream Identity Provider unavailable") while logging the sensitive details internally with `logger.exception()`. Do not include raw exception strings in the `message` field of custom exceptions exposed to the user.

### 10. Lack of Explicit HTTP Client Timeouts

**Severity:** Low

**Description:**
The `IdentityManagerAsync` initializes `httpx.AsyncClient()` without explicit timeout arguments. While `httpx` has default timeouts (typically 5s), relying on defaults is risky for a security-critical library, especially for the `connect`, `read`, and `write` pools. In high-latency failure modes, this can lead to the application hanging or thread pool exhaustion.

**Conceptual Solution:**
Explicitly configure **Aggressive Timeouts** (e.g., `timeout=httpx.Timeout(5.0, connect=2.0)`) and connection limits when initializing the `httpx.AsyncClient`. This ensures the library fails fast and recovers gracefully during network outages.
