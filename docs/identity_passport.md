# The Identity Passport

The "Identity Passport" is the canonical data structure representing an authenticated user's context within the CoReason ecosystem. It is implemented as the `UserContext` class in `coreason_identity`.

## Philosophy

As microservices proliferate, passing raw JWTs or ad-hoc dictionaries leads to inconsistency and security gaps. The Identity Passport serves as a strictly typed, immutable contract that every service can rely on. It "hydrates" the raw identity (IdP claims) into a platform-native format.

## Schema

The `UserContext` schema is designed to support:
1.  **Core Identity:** Who is this? (`user_id`, `email`)
2.  **Access Control:** What groups/roles do they have? (`groups`, `scopes`)
3.  **Delegation:** Can they act on behalf of someone else? (`downstream_token`)
4.  **Extensibility:** Custom attributes. (`claims`)

### Fields

| Field | Type | Description |
| :--- | :--- | :--- |
| `user_id` | `str` | The immutable subject ID (e.g., `sub` from OIDC). Unique identifier for the user. |
| `email` | `EmailStr` | The user's email address. Verified and strictly typed. Essential for audit logs and notifications. |
| `groups` | `List[str]` | Security group IDs. Used for **Row-Level Security (RLS)** in services like Catalog or Search. |
| `scopes` | `List[str]` | OAuth 2.0 scopes (e.g., `openid`, `profile`, `api:read`). Used for coarse-grained API permission checks. |
| `downstream_token` | `SecretStr` | The raw On-Behalf-Of (OBO) token. This is used when the service needs to call downstream APIs (e.g., Microsoft Graph) as the user. Stored as a `SecretStr` to prevent accidental logging. |
| `claims` | `Dict[str, Any]` | A dictionary containing any extended attributes or mapped legacy fields (e.g., `project_context`, `permissions`). |

## Usage Patterns

### 1. Basic Identity Check
```python
def get_current_user(token: str = Depends(oauth2_scheme)):
    user = identity_manager.validate_token(token)
    logger.info(f"Action by {user.user_id}")
    return user
```

### 2. Row-Level Security (RLS)
Services can pass `user.groups` to database queries to filter results.

```python
def search_documents(user: UserContext, query: str):
    # Only return docs where the user is in the allowed groups
    return db.search(query, allowed_groups=user.groups)
```

### 3. Delegated Calls (OBO)
When calling external APIs, use the `downstream_token`.

```python
import httpx

async def fetch_outlook_calendar(user: UserContext):
    if not user.downstream_token:
        raise Unauthorized("No delegation token available")

    token = user.downstream_token.get_secret_value()
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://graph.microsoft.com/v1.0/me/calendar",
            headers={"Authorization": f"Bearer {token}"}
        )
```

### 4. Legacy Migration
If you were using `project_context` or `permissions` fields directly, they are now available in `claims`:

```python
# Old
# project = user.project_context

# New
project = user.claims.get("project_context")
```
