# Design Decision: Strict Token Validation (Algorithms & Leeway)

## Context
Default JWT library behaviors are often too permissive for high-security environments.
1.  **Algorithm Confusion:** Libraries may accept multiple algorithms (e.g., HS256 and RS256) by default. If an attacker can force the server to use HS256 with the public key as the secret, they can forge tokens.
2.  **Clock Skew Leeway:** Libraries often allow a 60-300s window for expired tokens to be accepted. This allows expired tokens to be replayed for several minutes.

## Decision
We enforce strict security defaults to eliminate these risks.

### 1. Mandatory Algorithm Whitelisting
The `CoreasonVerifierConfig` now requires an explicit `allowed_algorithms` list (e.g., `['RS256']`). There is no default value.
*   **Implementation:** The `TokenValidator` initializes the underlying `JsonWebToken` processor with this strict allow-list. Any token header specifying an algorithm not in this list is rejected immediately.
*   **Benefit:** Prevents Key Confusion attacks and downgrades to weaker algorithms (e.g., `none`).

### 2. Zero-Tolerance Clock Skew
The `clock_skew_leeway` defaults to `0` seconds.
*   **Implementation:** The `leeway` parameter is explicitly passed to the `validate()` method of the claims processor.
*   **Benefit:** Tokens are rejected the instant they expire (`exp`) or before they are valid (`nbf`). This minimizes the window for replay attacks.

## Implementation Details

### Configuration
`CoreasonVerifierConfig` fields:
*   `allowed_algorithms: list[str]`: Mandatory. Example: `["RS256"]`.
*   `clock_skew_leeway: int`: Optional, defaults to `0`.

### Validation Logic
The `TokenValidator` constructs the `claims_options` dictionary with the configured leeway:
```python
def get_claims_options(iss: str) -> dict[str, Any]:
    return {
        "exp": {"essential": True, "leeway": self.leeway},
        "nbf": {"essential": False, "leeway": self.leeway},
        ...
    }
```

The underlying `Authlib` decoder is restricted:
```python
self.jwt = JsonWebToken(self.allowed_algorithms)
```

## Migration
Existing consumers must update their configuration to include `allowed_algorithms`.
```python
config = CoreasonVerifierConfig(
    ...,
    allowed_algorithms=["RS256"],  # New mandatory field
    clock_skew_leeway=0            # Optional, strict default
)
```
