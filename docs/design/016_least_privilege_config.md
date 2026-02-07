# 016: Least Privilege Configuration

## Status
Accepted

## Context
Previously, the `CoreasonIdentityConfig` class acted as a "God Object," containing fields for both token verification (e.g., `audience`, `issuer`) and client operations (e.g., `client_id`). This meant that services intended only to validate tokens (Verifiers) still had access to client configuration fields, violating the principle of **Least Privilege**.

Additionally, the `client_id` field was optional (`str | None`), leading to runtime checks and potential `NoneType` errors if a service attempted client operations without the necessary configuration.

## Decision
We have split the monolithic configuration into two distinct, immutable Pydantic models:

1.  **`CoreasonVerifierConfig` (The Base)**
    *   **Purpose:** For services that only need to validate incoming tokens (e.g., APIs, Gateways).
    *   **Fields:** `domain`, `audience`, `pii_salt`, `http_timeout`, `unsafe_local_dev`, `issuer`.
    *   **Constraint:** Does **NOT** contain `client_id`.

2.  **`CoreasonClientConfig` (The Subclass)**
    *   **Purpose:** For services or CLIs that need to act as OIDC Clients (e.g., initiating Device Flow, refreshing tokens).
    *   **Inheritance:** Inherits from `CoreasonVerifierConfig`.
    *   **Fields:** Adds `client_id` (Mandatory).

## Implementation Details

### Type Safety & Runtime Checks
The `IdentityManager` (and its async counterpart) now accepts the base `CoreasonVerifierConfig`. However, methods that require client credentials (like `start_device_login`) enforce strict type checking at runtime:

```python
def start_device_login(self):
    if not isinstance(self.config, CoreasonClientConfig):
        raise CoreasonIdentityError("Device login requires CoreasonClientConfig...")
    # Safe to access self.config.client_id
```

### Benefits
1.  **Security:** Pure verifier services cannot inadvertently or maliciously act as clients, as they lack the `client_id` in their configuration interface.
2.  **Clarity:** The intent of a service (Verifier vs. Client) is explicit at initialization time.
3.  **Robustness:** Eliminates `Optional[str]` ambiguity for `client_id`. If you have a `CoreasonClientConfig`, you are guaranteed to have a `client_id`.

## Migration
*   Replace `CoreasonIdentityConfig` with `CoreasonVerifierConfig` for standard API validation.
*   Replace `CoreasonIdentityConfig` with `CoreasonClientConfig` for CLIs or services needing device flow.
