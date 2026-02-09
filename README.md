# coreason-identity

Decoupled authentication middleware, abstracting OIDC and OAuth2 protocols from the main application.

[![Organization](https://img.shields.io/badge/org-CoReason--AI-blue)](https://github.com/CoReason-AI)
[![License](https://img.shields.io/badge/license-Prosperity%203.0-blue)](https://img.shields.io/badge/license-Prosperity%203.0-blue)
[![Build Status](https://github.com/CoReason-AI/coreason_identity/actions/workflows/build.yml/badge.svg)](https://github.com/CoReason-AI/coreason_identity/actions)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Documentation](https://img.shields.io/badge/docs-Product%20Requirements-green)](docs/product_requirements.md)

## Overview

`coreason-identity` ("The Bouncer") handles all Authentication (AuthN) and Role-Based Access Control (AuthZ) for the CoReason platform. It enforces a strict "Bouncer" philosophy: it checks IDs and checks lists but does not issue IDs.

The package standardizes:
*   **Protocol:** OIDC (OpenID Connect).
*   **Identity Provider:** Auth0 or Keycloak.
*   **Library:** Authlib.

## Features

Based on the [Product Requirements](docs/product_requirements.md):

*   **OIDCProvider:** Fetches and caches JWKS from the OIDC Discovery URL (LRU Cache).
*   **TokenValidator:** Validates JWT signatures, standard claims (`exp`, `iss`, `aud`), and enforces strict audience checks to prevent "Confused Deputy" attacks.
*   **IdentityMapper:** Maps IdP claims to a standardized `UserContext` model, handling project context extraction and group-to-permission mapping.
*   **DeviceFlowClient:** Implements RFC 8628 OAuth 2.0 Device Authorization Grant for headless CLI authentication.
*   **Observability:** Emits OpenTelemetry spans and secure logs (PII hashed).
*   **Security:** DNS-based SSRF protection, strict DoS limits, PII sanitization, and Replay Protection (JTI Cache). See [Security Hardening (SOTA)](docs/design/018_security_hardening.md).

## Installation

```bash
pip install coreason-identity
```

## Usage

### 1. Token Verification (Server-Side)

Use `CoreasonVerifierConfig` for services that only need to validate tokens (no client credentials required).

```python
from coreason_identity import IdentityManager, CoreasonVerifierConfig, InvalidTokenError
from pydantic import SecretStr

# Initialize (The Bouncer)
config = CoreasonVerifierConfig(
    domain="auth.coreason.com",
    audience="api://coreason",
    pii_salt=SecretStr("super-secret-salt-123"),  # Mandatory: for PII hashing
    http_timeout=5.0,  # Mandatory: fail fast if IdP is slow
    allowed_algorithms=["RS256"],  # Mandatory: algorithm allowlist
    clock_skew_leeway=0            # Optional: defaults to 0 (strict security)
)
identity = IdentityManager(config)

# Validate (The Check)
try:
    # Validate a raw Bearer token
    user_context = identity.validate_token(auth_header="Bearer eyJ...")

    # Access canonical Identity Passport fields
    print(f"User {user_context.user_id} ({user_context.email}) is active.")

    # Check groups for Row-Level Security
    if "admin" in user_context.groups:
        print("Admin access granted.")

except InvalidTokenError:
    # Handle invalid tokens (expired, bad signature, wrong audience, etc.)
    print("Access denied.")
```

### 2. Device Flow Login (CLI / Client-Side)

Use `CoreasonClientConfig` when the application acts as an OIDC Client (needs `client_id`).

```python
from coreason_identity import IdentityManager, CoreasonClientConfig

# Initialize (The Borrower)
config = CoreasonClientConfig(
    domain="auth.coreason.com",
    audience="api://coreason",
    client_id="my-cli-client-id",  # Mandatory for client operations
    pii_salt=SecretStr("super-secret-salt-123"),
    http_timeout=10.0,
    allowed_algorithms=["RS256"]
)
identity = IdentityManager(config)

# CLI Login (The Device Flow)
# Initiate the flow
flow = identity.start_device_login(scope="openid profile email")
print(f"Go to {flow.verification_uri} and enter {flow.user_code}")

# Poll for tokens
try:
    tokens = identity.await_device_token(flow)
    print("Login successful!")
    print(f"Access Token: {tokens.access_token}")
except Exception as e:
    print(f"Login failed: {e}")
```
