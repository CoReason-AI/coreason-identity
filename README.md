# coreason-identity (The Bouncer)

Decoupled authentication middleware, abstracting OIDC and OAuth2 protocols from the main application.

[![License](https://img.shields.io/badge/License-Prosperity%203.0-blue)](https://github.com/CoReason-AI/coreason_identity)
[![CI](https://github.com/CoReason-AI/coreason_identity/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/CoReason-AI/coreason_identity/actions/workflows/ci-cd.yml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Overview

**coreason-identity** is the Lead Security Architect for the CoReason platform, acting as "The Bouncer". It handles all Authentication (AuthN) and Role-Based Access Control (AuthZ) by checking IDs and lists, without minting its own tokens.

### Mission
*   **Validate:** Verifies JWT signatures against Identity Provider (IdP) JWKS.
*   **Enforce:** Maps Group-to-Project mappings for robust RBAC.
*   **Facilitate:** Manages the OAuth2 Device Code Flow for CLI tools.

## Features

*   **OIDC Integration:** Fetches and caches JWKS from standard OIDC Discovery endpoints.
*   **Token Validation:** Strict validation of `exp`, `iss`, and `aud` claims using `Authlib`.
*   **Confused Deputy Protection:** Enforces strict Audience checks.
*   **Identity Mapping:** Normalizes IdP claims (groups/roles) into a standardized `UserContext`.
*   **CLI Authentication:** Implements RFC 8628 (Device Authorization Grant) for headless login.
*   **Observability:** Emits OpenTelemetry spans for every validation attempt and logs safely (PII redacted).
*   **Secure by Default:** No custom crypto; uses industry-standard libraries (`Authlib`, `Pydantic`).

## Installation

Install via pip:

```bash
pip install coreason-identity
```

Or with Poetry:

```bash
poetry add coreason-identity
```

## Usage

### Middleware Integration

Initialize the manager and use it to validate incoming Bearer tokens.

```python
from coreason_identity import IdentityManager, CoreasonIdentityConfig, InvalidTokenError

# 1. Initialize (The Borrowing)
# Configuration can also be loaded from environment variables (COREASON_AUTH_DOMAIN, etc.)
config = CoreasonIdentityConfig(
    domain="auth.coreason.com",
    audience="api://coreason"
)
identity = IdentityManager(config)

# 2. Validate (The Bouncer)
auth_header = "Bearer eyJhbGciOiJSUzI1NiIs..." # From HTTP Header

try:
    user_context = identity.validate_token(auth_header=auth_header)
    print(f"User {user_context.sub} is authorized.")
    print(f"Project Context: {user_context.project_context}")
    print(f"Permissions: {user_context.permissions}")
except InvalidTokenError as e:
    print(f"Access Denied: {e}")
```

### CLI Device Login

Authenticate a CLI tool using the Device Code Flow.

```python
# Ensure client_id is set in config
config = CoreasonIdentityConfig(
    domain="auth.coreason.com",
    audience="api://coreason",
    client_id="my-cli-client-id"
)
identity = IdentityManager(config)

# 3. CLI Login (The Device Flow)
flow = identity.start_device_login()
print(f"Go to {flow.verification_uri} and enter {flow.user_code}")

try:
    tokens = identity.await_device_token(flow)
    print(f"Access Token: {tokens.access_token}")
except Exception as e:
    print(f"Login failed: {e}")
```

## Development

1.  **Install dependencies:**
    ```bash
    poetry install
    ```

2.  **Run linting and formatting:**
    ```bash
    poetry run ruff format .
    poetry run ruff check --fix .
    ```

3.  **Run tests:**
    ```bash
    poetry run pytest
    ```
