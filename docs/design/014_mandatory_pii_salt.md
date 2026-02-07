# Mandatory PII Salt Enforcement

## 1. Overview

In version `0.9.0` (and later), the `pii_salt` configuration field in `CoreasonIdentityConfig` has been made **mandatory**. The previously existing default value (`"coreason-unsafe-default-salt"`) has been removed.

This is a **BREAKING CHANGE**.

## 2. Motivation

The presence of a hardcoded default salt presented a significant security risk (Finding #7 - Insecure Defaults). If a consumer deployed `coreason-identity` to production without explicitly configuring `COREASON_AUTH_PII_SALT`, user IDs would be hashed using a publicly known salt. This would allow an attacker with access to the logs or telemetry to de-anonymize user identities via rainbow table attacks.

By making the field mandatory, we force the consumer to explicitly provide a secret, high-entropy salt, thereby ensuring the integrity of PII anonymization.

## 3. Implementation

*   **`CoreasonIdentityConfig`**: The `pii_salt` field definition was changed from having a default value to being required (`Field(...)`).
*   **Validation**: Initializing the configuration without providing `pii_salt` (either via constructor or environment variable) will now raise a `pydantic.ValidationError`.
*   **Testing**: The test suite has been updated to inject a dummy salt via `conftest.py`, ensuring that unit tests do not fail due to this change, while explicitly testing the validation logic in `tests/test_config.py`.

## 4. Migration Guide

Consumers upgrading to this version must ensure that they provide a `pii_salt`.

### Environment Variable (Recommended)

Set the `COREASON_AUTH_PII_SALT` environment variable in your deployment:

```bash
export COREASON_AUTH_PII_SALT="your-generated-high-entropy-secret-salt"
```

### Constructor

Or pass it explicitly when initializing the config:

```python
config = CoreasonIdentityConfig(
    ...,
    pii_salt=SecretStr("your-generated-high-entropy-secret-salt")
)
```
