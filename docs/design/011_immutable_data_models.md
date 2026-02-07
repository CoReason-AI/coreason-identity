# Immutable Data Models

## Context

The coreason-identity package serves as a critical security component (Identity Bouncer) within the middleware stack. It is responsible for validating tokens, mapping identities, and providing a trusted `UserContext` to downstream services.

Historically, the data models (`UserContext`, `CoreasonIdentityConfig`) were mutable. this posed significant risks:
1.  **Downstream Tampering:** A bug or malicious code in a downstream service could modify the `UserContext` (e.g., adding a scope or group), effectively escalating privileges for subsequent operations in the same request context.
2.  **Thread Safety:** Mutable shared state is inherently unsafe in concurrent environments, potentially leading to race conditions.
3.  **Configuration Drift:** Runtime logic could accidentally modify the global configuration, causing unpredictable behavior across the application lifecycle.

## Decision

We have enforced strict immutability on all public-facing data models.

### 1. Frozen Pydantic Models

All core data models are now configured with `frozen=True`:

```python
class UserContext(BaseModel):
    model_config = ConfigDict(frozen=True)
    # ...
```

This ensures that any attempt to reassign a field (e.g., `user.user_id = "new"`) raises a `ValidationError` (or `TypeError`).

### 2. Immutable Collection Types

To prevent deep mutation (e.g., `user.scopes.append("admin")`), we have transitioned from `list` to `tuple` for collection fields:

-   `UserContext.groups`: `list[str]` -> `tuple[str, ...]`
-   `UserContext.scopes`: `list[str]` -> `tuple[str, ...]`

This guarantees that the collections themselves cannot be modified in place.

### 3. Copy-on-Write Semantics

Code that needs to "modify" these objects (e.g., during the identity mapping phase) must now use a copy-on-write approach, creating a new instance with the updated values:

```python
# Old (Mutable)
user.scopes.append("new_scope")

# New (Immutable)
new_scopes = user.scopes + ("new_scope",)
user = user.model_copy(update={"scopes": new_scopes})
```

## Impact

-   **Security:** "Zero-Copy Security" is reinforced. The `UserContext` passed to downstream services is guaranteed to remain exactly as it was when validated by the Identity Bouncer.
-   **Stability:** Configuration remains constant throughout the application lifecycle.
-   **Developer Experience:** Attempting to mutate these objects will result in immediate, clear errors, preventing subtle bugs.

## Testing Strategy

Tests verify:
1.  **Assignment Blocking:** Assert that `user.field = value` raises `ValidationError`.
2.  **Mutation Blocking:** Assert that `user.collection.append(value)` raises `AttributeError`.
3.  **Copy-on-Write:** Assert that `model_copy()` creates a new, independent instance.
4.  **Serialization:** Assert that models can still be serialized/pickled correctly.
