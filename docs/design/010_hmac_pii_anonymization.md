# HMAC PII Anonymization and Telemetry Security

## 1. Overview

To mitigate privacy vulnerabilities related to User ID logging and telemetry leakage (Finding #6), `coreason-identity` now enforces strict HMAC-SHA256 anonymization for all PII logged to internal systems or sent to observability platforms (OpenTelemetry).

Previously, User IDs were hashed using unsalted SHA-256, which is vulnerable to rainbow table attacks given the low entropy of many user identifiers (e.g., incremental integers or short strings). Furthermore, raw User IDs were inadvertently sent as OpenTelemetry span attributes.

## 2. Solution: Salted HMAC-SHA256

We have replaced the unsalted hashing with **HMAC-SHA256** using a configurable secret salt.

### Configuration

A new configuration field `pii_salt` has been added to `CoreasonIdentityConfig`.

*   **Env Variable:** `COREASON_AUTH_PII_SALT`
*   **Type:** `SecretStr`
*   **Default:** `SecretStr("coreason-unsafe-default-salt")` (Backward compatible, but **strongly recommended** to override in production).

### Mechanism

When a token is validated:
1.  The `TokenValidator` extracts the `sub` (Subject/User ID) claim.
2.  It computes an HMAC-SHA256 hash using the configured `pii_salt` as the key and the User ID as the message.
3.  This **anonymized hash** is used for:
    *   Application logs (e.g., `Token validated for user <hash>`).
    *   OpenTelemetry Span Attributes (`user.id` = `<hash>`).

The raw User ID is **never** written to logs or traces.

## 3. Implementation Details

*   **`TokenValidator`**: Now accepts `pii_salt` in its constructor. The `_anonymize(value: str)` method encapsulates the HMAC logic.
*   **`IdentityManagerSync`**: Propagates the salt from the global configuration to the validator.
*   **OpenTelemetry**: The span attribute `user.id` is explicitly set to the anonymized value.

## 4. Security Considerations

*   **Salt Rotation**: If the `pii_salt` is changed, all historical logs and traces will no longer correlate with new activity for the same user. This is a trade-off for security.
*   **Uniqueness**: The HMAC is deterministic for a given salt, preserving the ability to correlate actions by the same user within a single logging epoch/salt lifecycle without revealing their identity.
