# Product Requirements Document: coreason-identity

## System Instruction: Architecting coreason-identity
**Role:** You are the Lead Security Architect for the CoReason platform.
**Objective:** Architect and implement the coreason-identity Python package.
**Philosophy:** "The Bouncer." This package checks IDs and checks lists. It does not issue IDs (that is the IdP's job).

## Overview

*   **Package Name:** `coreason-identity` (The Bouncer)
*   **Mission:** Handles all Authentication (AuthN) and Role-Based Access Control (AuthZ).
*   **Responsibilities:**
    *   Validates JWT signatures against Identity Provider (IdP) JWKS.
    *   Enforces Group-to-Project mapping (RBAC).
    *   Manages the OAuth2 Device Code Flow for CLI tools.
*   **Technology Stack (Standardization):**
    *   **Protocol:** OIDC (OpenID Connect). The middleware should never mint its own tokens.
    *   **Primary Identity Provider:** Auth0 or Keycloak.
    *   **Library:** Authlib or PyJWT.
    *   **Directive:** Use Authlib to validate tokens issued by the IdP. Do not implement custom login handlers; offload all flow initiation to the IdP.

## Agent Instructions

### 1. The "Borrow Over Build" Directive (Strict Constraints)
You are strictly forbidden from writing custom cryptographic or authentication logic. You must wrap industry-standard libraries.

*   **Protocol:** OpenID Connect (OIDC).
*   **Primary Library:** Authlib (for OIDC integration and JWT validation).
*   **Data Validation:** Pydantic V2 (strict typing).
*   **Forbidden:**
    *   Do NOT use python-jose or PyJWT directly if Authlib can handle the task (consolidate dependencies).
    *   Do NOT implement custom login forms or password handling.
    *   Do NOT implement custom JWT decoding regex or header parsing.
    *   Do NOT mint/sign tokens. This package is a consumer of tokens, not an issuer.

### 2. Business Logic Specifications (The Source of Truth)
Do not rely on external file analysis. The following specifications define the required business logic that must be re-implemented using standard libraries.

#### 2.1 The User Identity Model
The system requires a standardized User Context object to be available throughout the middleware stack.

*   **Source Data:** The raw JWT claims from the IdP (e.g., Auth0).
*   **Transformation Logic (The Mapper):**
    *   **User ID (sub):** Use the standard OIDC sub claim.
    *   **Email:** Extract email claim. Mark as PII.
    *   **Project Context:**
        *   Look for a custom claim `https://coreason.com/project_id`.
        *   **Fallback:** If missing, check the groups list. If a group matches the pattern `project:<id>`, extract `<id>` as the project context.
    *   **Permissions:**
        *   Look for a `permissions` claim (list of strings).
        *   **Fallback:** Map groups to permissions (e.g., if group is admin, assign `["*"]`).
*   **Target Output (Pydantic Model):**

```python
class UserContext(BaseModel):
    sub: str
    email: EmailStr
    project_context: Optional[str]
    permissions: List[str] = Field(default_factory=list)
```

#### 2.2 CLI Authentication Strategy
The CLI tools require a headless authentication mechanism.

*   **Requirement:** Implement the OAuth 2.0 Device Authorization Grant (RFC 8628).
*   **Flow:**
    1.  Client requests a code from IdP.
    2.  User visits a URL (displayed in CLI) to approve.
    3.  Client polls IdP for tokens.
*   **Constraint:** Do not build custom routes. Use the IdP's `/oauth/device/code` and `/oauth/token` endpoints directly.

### 3. Package Architecture & Components
The package must expose a simple, synchronous (or async compatible) API. It should be composed of three distinct functional domains:

#### Component A: OIDCProvider (The Source of Truth)
*   **Input:** An OIDC Discovery URL (e.g., `https://my-tenant.auth0.com/.well-known/openid-configuration`).
*   **Responsibility:**
    *   On startup, fetch the JWKS (JSON Web Key Set) and cached configuration.
    *   Provide a robust caching mechanism (LRU Cache) for public keys to prevent hitting the IdP on every request.
*   **Output:** A verified cryptographic key set ready for signature validation.

#### Component B: TokenValidator (The Gatekeeper)
*   **Input:** A raw Bearer Token string (JWT).
*   **Responsibility:**
    *   Validate the Signature using keys from Component A.
    *   Validate standard Claims: `exp` (Expiry), `iss` (Issuer), `aud` (Audience).
    *   **Crucial:** Enforce strict Audience checks to prevent "Confused Deputy" attacks.
*   **Output:** A validated, raw dictionary of claims OR raise a CredentialError.

#### Component C: IdentityMapper (The RBAC Engine)
*   **Input:** Validated Claims Dictionary (from Component B).
*   **Responsibility:**
    *   Map the IdP's diverse claims (e.g., `https://coreason.com/groups` or roles) into the standardized internal CoReason User Model defined in Section 2.1.
*   **Output:** A Pydantic `UserContext` object containing:
    *   `sub` (Immutable User ID)
    *   `email` (PII)
    *   `permissions` (List[str], e.g., `["agent:run", "budget:view"]`)
    *   `project_context` (Tenant ID)

#### Component D: DeviceFlowClient (The CLI Helper)
*   **Input:** Client ID, Scope, and IdP URL.
*   **Responsibility:**
    *   Implement the RFC 8628 OAuth 2.0 Device Authorization Grant.
    *   Provide methods to:
        *   `initiate_flow() -> Returns verification URI and User Code.`
        *   `poll_token() -> Polls the token endpoint until the user approves or timeout.`
*   **Output:** A Refresh Token and Access Token (securely returned to the calling CLI).

### 4. Operational Requirements
*   **Configuration:** The package must be configured via a Pydantic Settings object (e.g., `CoreasonIdentityConfig`), injectable via environment variables (`COREASON_AUTH_DOMAIN`, `COREASON_AUTH_AUDIENCE`).
*   **Error Handling:** Define specific exceptions:
    *   `TokenExpiredError`
    *   `InvalidAudienceError`
    *   `SignatureVerificationError`
    *   `InsufficientPermissionsError`
*   **Observability:** Emit OpenTelemetry spans for every validation attempt. Log strictly: "Token validated for user [HASH]" or "Validation failed: [Reason]". NEVER log the token itself.

### 5. Definition of Done (The Output)
The agent must generate a Python package structure that allows the consuming middleware (coreason-api) to write code exactly like this:

```python
# Intended Usage Example (Do NOT implement this, just enable it)

from coreason_identity import IdentityManager, CoreasonIdentityConfig

# 1. Initialize (The Borrowing)
config = CoreasonIdentityConfig(domain="auth.coreason.com", audience="api://coreason")
identity = IdentityManager(config)

# 2. Validate (The Bouncer)
try:
    user_context = identity.validate_token(auth_header="Bearer eyJ...")
    print(f"User {user_context.sub} is authorized for project {user_context.project_context}")
except InvalidTokenError:
    deny_access()

# 3. CLI Login (The Device Flow)
flow = identity.start_device_login(scope="openid profile email")
print(f"Go to {flow.verification_uri} and enter {flow.user_code}")
tokens = identity.await_device_token(flow)
```
