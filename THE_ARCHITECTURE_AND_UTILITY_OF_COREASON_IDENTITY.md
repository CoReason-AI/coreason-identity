# The Architecture and Utility of coreason-identity

### 1. The Philosophy (The Why)
In the complex ecosystem of modern microservices, authentication is often fragmented. Developers frequently reinvent the wheel, writing custom JWT parsers or creating brittle logic to map Identity Provider (IdP) claims to internal application roles. This leads to security vulnerabilities ("Confused Deputy" attacks) and inconsistent authorization policies across services.

**coreason-identity** was built to solve this by acting as **"The Bouncer"** of the CoReason platform. Its philosophy is simple: **Check IDs and check lists.** It does not mint tokens—that is the job of the Identity Provider (e.g., Auth0 or Keycloak). Instead, this package serves as the trusted middleware that stands between the raw, chaotic world of OIDC tokens and the clean, structured logic of domain services.

By rigidly separating authentication (AuthN) from authorization (AuthZ) mapping, it ensures that every service receives a standardized, validated `UserContext`, stripping away the complexity of cryptography and protocol negotiation from the business logic.

### 2. Under the Hood (The Dependencies & logic)
The architecture follows a "Borrow Over Build" directive, wrapping industry-standard libraries to provide a secure, opinionated implementation.

*   **Authlib** serves as the cryptographic backbone. Rather than implementing custom JWT decoding or signature verification (which is prone to error), `coreason-identity` leverages Authlib for strictly compliant OpenID Connect (OIDC) integration and JSON Web Key Set (JWKS) validation.
*   **Pydantic V2** enforces the data contract. It ensures that the output of the bouncer is always a strictly typed `UserContext` object, eliminating runtime `KeyError`s when accessing user claims.
*   **HTTPX** handles the network layer with modern, async-compatible capabilities. It powers the retrieval of public keys (JWKS) and manages the polling loops required for the OAuth 2.0 Device Authorization Grant.
*   **OpenTelemetry & Loguru** provide observability. The system is designed to be audible but private, emitting trace spans for every validation attempt while strictly hashing Personally Identifiable Information (PII) in logs.

Internally, the `IdentityManager` orchestrates a pipeline:
1.  **Auto-Discovery:** It fetches the OIDC configuration from the IdP.
2.  **Validation:** It cryptographically verifies the token signature and strictly checks the `aud` (audience) claim to prevent token misuse.
3.  **Mapping:** It transforms abstract IdP groups into concrete application project contexts, while enforcing strict permission mapping without implicit privilege escalation.

### 3. Immutable Data Integrity
To prevent tampering and ensure thread safety, all core data structures (`UserContext`, `CoreasonIdentityConfig`) are deeply immutable.
*   **Frozen Models:** Attempting to assign to a field (e.g., `user.user_id = "new"`) raises a `ValidationError`.
*   **Tuple Collections:** Lists are replaced with tuples (e.g., `user.scopes` is `tuple[str, ...]`), preventing in-place mutation like `.append()`.

### 3. In Practice (The How)
The package exposes a single, high-level entry point: `IdentityManagerSync` (or `IdentityManagerAsync`).

#### The Bouncer (Server-Side Validation)
This is the primary use case for APIs. The middleware initializes the manager once and uses it to convert raw HTTP headers into a usable user context.

```python
from coreason_identity import IdentityManagerSync, CoreasonIdentityConfig, InvalidTokenError

# 1. Initialize with strict configuration (The Borrowing)
config = CoreasonIdentityConfig(
    domain="auth.coreason.com",
    audience="api://coreason-platform"
)
identity = IdentityManagerSync(config)

# 2. Validate incoming requests (The Bouncer)
try:
    # Turns "Bearer eyJ..." into a strictly typed object
    user = identity.validate_token(auth_header="Bearer <token>")

    print(f"User {user.user_id} is acting in context.")

    # Check scopes/permissions
    if "admin:write" in user.scopes:
        perform_privileged_action()

    # Access legacy project context via claims
    project = user.claims.get("project_context")
    if project:
        print(f"Acting in project {project}")

except InvalidTokenError:
    # Fail closed on any signature or claim error
    raise_401_unauthorized()
```

#### The Helper (CLI Device Flow)
For command-line tools where a browser isn't available or convenient, the package implements the RFC 8628 Device Flow.

```python
# 1. Start the headless login process
flow = identity.start_device_login()
print(f"Please visit: {flow.verification_uri}")
print(f"And enter code: {flow.user_code}")

# 2. Poll until the user approves in their browser
try:
    tokens = identity.await_device_token(flow)
    print(f"Login successful! Access Token: {tokens.access_token[:10]}...")
except Exception as e:
    print(f"Login failed: {e}")
```
