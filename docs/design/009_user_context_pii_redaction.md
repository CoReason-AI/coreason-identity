# User Context PII Redaction ("Zero-Copy Security")

## 1. Overview

To adhere to "Zero-Copy Security" principles and preventing Sensitive Data Exposure (OWASP Top 10), the `UserContext` model in `coreason-identity` explicitly enforces redaction of Personally Identifiable Information (PII) in its string representations.

The `claims` dictionary, which contains raw JWT claims (potentially including addresses, phone numbers, and custom sensitive attributes), is **never** output in `__repr__` or `__str__` calls.

## 2. Mechanism

The `UserContext` class (inheriting from Pydantic's `BaseModel`) overrides the default string representation methods:

*   **`__repr__`**: Returns a string resembling the class signature but replaces the value of the `claims` field with the literal string `'<REDACTED>'`.
*   **`__str__`**: Proxies to `__repr__`.

### Redacted Output Example
```python
UserContext(user_id='auth0|123', email='alice@example.com', groups=['admin'], scopes=['openid'], downstream_token=SecretStr('**********'), claims='<REDACTED>')
```

### Unaffected Fields
The following fields remain visible to aid in debugging and audit trails:
*   `user_id` (Immutable Subject ID)
*   `email` (Essential identity, though PII, it is required for context; strict logs should mask this at the sink level if necessary, but here it serves as the identifier)
*   `groups` (RBAC context)
*   `scopes` (OAuth2 permissions)
*   `downstream_token` (Handled safely via `SecretStr`)

## 3. Data Integrity

This protection applies **only** to the string representation (logging/printing). The underlying data storage is untouched.

*   **Programmatic Access:** `user_ctx.claims` returns the original dictionary containing all data.
*   **Application Logic:** Downstream consumers (e.g., policy engines) can access the raw claims as needed.

## 4. Rationale

Standard Pydantic models output all fields in `__repr__`. If a developer writes `logger.info(f"Context: {user_ctx}")`, the entire `claims` dictionary—potentially containing sensitive data like `social_security_number` or `home_address`—would be written to plain-text logs.

By enforcing redaction at the model level, we ensure that accidental logging does not result in a data leak.
