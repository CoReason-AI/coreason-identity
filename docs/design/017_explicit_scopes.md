# 017: Explicit Scopes Enforcement

## Status
Accepted

## Context
Previously, `IdentityManager.start_device_login` and `DeviceFlowClient` had a default value for the `scope` parameter: `"openid profile email"`. This was intended to simplify developer experience.

However, this "helpful" default violated the **Principle of Least Privilege**. Services were inadvertently requesting more PII (like `email`) than they strictly required, violating data minimization principles. It also created implicit coupling between the library and a specific IdP configuration.

## Decision
We have removed all default values for `scope` parameters in the Device Authorization Flow. Developers must now explicitly specify the scopes they require.

### Changes
1.  **`IdentityManager.start_device_login(scope: str)`**:
    *   The `scope` argument is now mandatory (runtime check).
    *   Previously: `scope="openid profile email"` (default).
    *   Now: Raises `ValueError` if `scope` is missing, empty, or whitespace-only.

2.  **`DeviceFlowClient.__init__(..., scope: str)`**:
    *   The `scope` argument is now mandatory (no default).

## Rationale
1.  **Least Privilege:** By forcing developers to think about scopes, we encourage requesting only what is necessary (e.g., just `openid` for authentication without profile data).
2.  **Data Minimization:** Reduces accidental exposure of PII.
3.  **Explicit > Implicit:** The code becomes self-documenting regarding its access requirements.

## Migration Guide
Any code calling `start_device_login()` without arguments will now fail with a `ValueError`.

**Before:**
```python
flow = identity.start_device_login()
```

**After:**
```python
# Explicitly request required scopes
flow = identity.start_device_login(scope="openid profile email")
```
