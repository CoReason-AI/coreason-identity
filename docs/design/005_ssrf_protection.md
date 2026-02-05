# SSRF Protection

## 1. Overview

`coreason-identity` enforces strict Server-Side Request Forgery (SSRF) protection within the configuration layer (`CoreasonIdentityConfig`). This prevents the application from being configured with a malicious OIDC Discovery URL that resolves to internal infrastructure (e.g., `localhost`, AWS Metadata Service, private subnets).

## 2. Mechanism

The `validate_domain_dns` validator in `src/coreason_identity/config.py` performs the following checks when the configuration is loaded:

1.  **Resolution:** Resolves the configured `domain` hostname to its IP address(es) using `socket.getaddrinfo`.
2.  **IP Validation:** Checks each resolved IP address against prohibited ranges using the Python standard library `ipaddress` module.
3.  **Prohibited Ranges:**
    *   **Private:** RFC 1918 (e.g., `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`).
    *   **Loopback:** `127.0.0.0/8` and `::1`.
    *   **Link-Local:** `169.254.0.0/16`.
    *   **Multicast:** `224.0.0.0/4`.
    *   **Reserved:** IETF reserved ranges.

If any resolved IP falls into these categories, a `ValueError` is raised, preventing the application from starting.

## 3. Limitations

*   **TOCTOU / DNS Rebinding:** This protection validates the domain at *configuration time*. It does not prevent DNS Rebinding attacks where the DNS record is changed *after* the check but *before* the HTTP request is made by the OIDC provider. Preventing this requires pinning the resolved IP or using a custom transport layer that re-verifies the IP on every connection, which is outside the current scope of this library.
*   **Resolution Differences:** While unlikely, discrepancies between the system resolver used by `socket` and the resolver used by the HTTP client (`httpx`) could theoretically lead to bypasses, though both typically rely on the underlying OS.

## 4. Development Bypass

For local development or testing in isolated environments where internal OIDC providers (like Keycloak on `localhost`) are necessary, the protection can be explicitly bypassed.

**Environment Variable:** `COREASON_DEV_UNSAFE_MODE="true"`

**Warning:** This should **NEVER** be enabled in production environments.
