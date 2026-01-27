# The Identity Passport: Delegated Access & Zero-Copy Security

## The Metaphor

The `coreason-identity` package acts as the central authority for user identity within the CoReason platform. Think of it as the issuer of a **"Passport"** (represented by the `UserContext` object).

When a request hits the **API Gateway** (`coreason-api`), the system validates the incoming OIDC token and issues this Passport. From that point forward, every service in the ecosystem trusts this Passport. It travels with the request, eliminating the need for redundant validation and ensuring a consistent identity context across all boundaries.

## The Structure

The Passport is realized as the `UserContext` Pydantic model. It contains strict fields that define the user's identity and capabilities.

### `UserContext` Fields

*   **`user_id`** (`str`):
    The immutable subject identifier (e.g., `sub` from the OIDC provider). This is the source of truth for *who* the user is.

*   **`groups`** (`List[str]`):
    A list of group identifiers the user belongs to. This is primarily used for **Row-Level Security (RLS)** in the Catalog (`coreason-catalog`), ensuring users only see data they are authorized to access.

*   **`downstream_token`** (`SecretStr`):
    The "On-Behalf-Of" (OBO) token. This is a sensitive credential used to access downstream services like Microsoft 365 or SharePoint via `coreason-connect`. It is wrapped in a `SecretStr` to prevent accidental exposure.

## The Rules

To maintain the integrity and security of the "Shared Kernel" architecture, all services must adhere to the following rules:

### Rule 1: Zero-Copy Security
**Never unwrap the `downstream_token` until the last mile.**
The `downstream_token` is strictly for use by `coreason-connect`. No other service should attempt to peek inside, decrypt, or use this token. It should be passed along blindly as part of the Passport.

### Rule 2: Strict Logging Hygiene
**Never log the `UserContext` as a raw string.**
The `UserContext` contains secrets (the `downstream_token`). Logging the entire object as a string risks leaking credentials into logs. Always use structured logging and specific fields (like `user_id`) when recording audit trails.

### Rule 3: Explicit Dependency Injection
**All inter-service communication must pass this object explicitly.**
Do not rely on global state or thread-local storage. The `UserContext` must be explicitly passed as an argument to functions and services (Dependency Injection). This ensures that every action is clearly attributable to a specific user and that the "On-Behalf-Of" context is preserved.
