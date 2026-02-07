# 010. Explicit Issuer Trust

**Date:** 2026-02-06
**Status:** Approved
**Author:** Security Engineering

## Context

Prior to this change, the `TokenValidator` component utilized **Implicit Issuer Trust** (also known as Trust-On-First-Use). When an `issuer` was not explicitly provided in the configuration, the validator would dynamically query the OIDC Discovery Endpoint (`.well-known/openid-configuration`) of the configured domain to determine the expected issuer.

### The Vulnerability

This implicit trust model introduced a vulnerability where an attacker capable of spoofing DNS or performing a Man-in-the-Middle (MITM) attack during the application's startup phase could inject a malicious issuer URL (e.g., `https://attacker.com`). The application would then trust this malicious issuer and subsequently validate tokens signed by the attacker, effectively bypassing authentication.

## Decision

We have enforced **Explicit Issuer Trust**. The application now requires a hardcoded, trusted issuer string to be determined at configuration time. The `TokenValidator` strictly enforces that the `iss` (issuer) claim in all tokens matches this configured value.

### Key Changes

1.  **Configuration (`CoreasonIdentityConfig`):**
    *   Added an `issuer` field (`str | None`).
    *   Implemented a `model_validator` that automatically derives a secure default issuer (`https://{domain}/`) from the `domain` field if `issuer` is not explicitly provided.
    *   This ensures that an issuer string is always available and determined before any network calls are made.

2.  **Validator (`TokenValidator`):**
    *   The `issuer` argument in `__init__` is now **mandatory**.
    *   Removed logic that fetched the issuer from `OIDCProvider.get_issuer()`.
    *   The `validate_token` method now strictly checks the `iss` claim against the locally configured `issuer` string.

3.  **Manager (`IdentityManager`):**
    *   Updated to pass the `issuer` from `CoreasonIdentityConfig` when initializing the `TokenValidator`.

## Consequences

*   **Security:** Eliminates the risk of trusting a malicious issuer via discovery spoofing. The "Source of Truth" for the issuer is now the trusted configuration, not the remote endpoint.
*   **Flexibility:** The default derivation handles the common case (`https://{domain}/`), while the optional `issuer` config field allows support for IdPs with non-standard issuer URLs (e.g., without trailing slashes or different hosts).
*   **Breaking Changes:**
    *   `TokenValidator` initialization signature has changed (issuer is mandatory).
    *   Applications relying on purely dynamic issuer discovery (where the issuer domain might differ entirely from the config domain without manual override) will fail fast, which is the intended security behavior.
