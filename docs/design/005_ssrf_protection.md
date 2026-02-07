# SSRF Protection

## 1. Overview

`coreason-identity` enforces strict **runtime** Server-Side Request Forgery (SSRF) protection. This prevents the application from connecting to internal infrastructure (e.g., `localhost`, AWS Metadata Service, private subnets) via malicious OIDC Discovery URLs, even in the face of sophisticated attacks like DNS Rebinding.

## 2. Mechanism: SafeHTTPTransport

The library uses a custom `httpx` transport layer, `SafeHTTPTransport`, which is active for all OIDC operations.

### Key Features:
1.  **DNS Pinning:** The hostname is resolved to an IP address immediately before the connection is established.
2.  **Runtime IP Validation:** The resolved IP is checked against prohibited ranges (RFC 1918 Private, Loopback, Link-Local, Multicast, Reserved).
3.  **Connection Forcing:** The HTTP client is forced to connect to the *validated IP address*, ensuring that the destination cannot change between check and use (TOCTOU).
4.  **SNI/SSL Integrity:** The original hostname is preserved for SNI (Server Name Indication) and SSL certificate verification, ensuring secure HTTPS connections even when connecting by IP.

## 3. Security Guarantee

This mechanism provides a stronger guarantee than previous configuration-time checks:

*   **Prevents TOCTOU:** By pinning the IP at the transport layer, we eliminate the time window for DNS Rebinding attacks.
*   **Fail Safe:** The transport fails closed. If a domain resolves to a blocked IP, the connection is never attempted.

## 4. Development Bypass

For local development or testing in isolated environments where internal OIDC providers (like Keycloak on `localhost`) are necessary, the protection can be strictly bypassed.

*   **Config:** `unsafe_local_dev=True`
*   **Env:** `COREASON_AUTH_UNSAFE_LOCAL_DEV=True`

**Warning:** This should **NEVER** be enabled in production environments.
