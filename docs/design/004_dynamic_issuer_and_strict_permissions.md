# Design Document: Dynamic Issuer Discovery & Strict Permission Mapping

## 1. Problem Statement

Two significant issues were identified in the previous implementation of `coreason-identity`:

1.  **Brittle Issuer Validation:** The `IdentityManagerSync` manually constructed the expected OIDC Issuer URL by appending a trailing slash to the configured domain. This caused validation failures for Identity Providers (IdPs) that do not use trailing slashes in their issuer claims, leading to operational fragility.
2.  **Implicit Privilege Escalation:** The `IdentityMapper` contained logic that automatically granted `["*"]` permissions to any user belonging to a group named "admin" (case-insensitive). This implicit mapping posed a security risk, as group names from external IdPs might be created by delegated administrators or come from untrusted sources, leading to accidental privilege escalation.

## 2. Solution

### 2.1 Dynamic Issuer Discovery (Deprecated)

**Update (2026-02-06):** This section is partially superseded by [010_explicit_issuer_trust.md](./010_explicit_issuer_trust.md). While dynamic discovery of keys (JWKS) remains, dynamic discovery of the *issuer string* for validation purposes has been removed to mitigate Implicit Issuer Trust vulnerabilities. The application now requires an explicit issuer (configured or derived locally).

*   **Mechanism:** The `OIDCProvider` fetches the `.well-known/openid-configuration` document from the IdP.
*   **Validation:** The `issuer` field from this document is treated as the source of truth.
*   **Implementation:**
    *   `OIDCProvider` now caches the entire OIDC configuration, not just the JWKS.
    *   `TokenValidator` accepts `issuer=None` during initialization.
    *   During validation, if the issuer is not explicitly configured, `TokenValidator` asynchronously retrieves the authoritative issuer string from `OIDCProvider.get_issuer()`.
    *   This ensures that the validated token's `iss` claim exactly matches what the IdP declares, regardless of trailing slashes or protocol variations (http vs https).

### 2.2 Strict Permission Mapping

The implicit mapping logic has been removed to enforce a "secure by default" posture.

*   **Change:** The `IdentityMapper` no longer checks for an "admin" group to assign permissions.
*   **New Behavior:** Permissions must be explicitly provided in the token claims (e.g., via a `permissions` claim) or handled by downstream services based on the raw `groups` list.
*   **Impact:** This prevents a scenario where creating a group simply named "admin" in the IdP inadvertently grants superuser access within the CoReason platform.

## 3. Impact & Migration

*   **Configuration:** No configuration changes are required for consumers. The system automatically adapts to the IdP's issuer format.
*   **Security:** The removal of implicit admin mapping is a breaking change for any system relying solely on group-name-based permissioning without explicit claims. These systems must now configure the IdP to emit explicit permission claims or implement their own authorization logic based on the `groups` field in the `UserContext`.
*   **Reliability:** Issuer validation is now robust against minor configuration differences (e.g., missing trailing slashes in `COREASON_AUTH_DOMAIN`).
