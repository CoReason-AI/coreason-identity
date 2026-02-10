# SSRF Protection

## 1. Overview

**CRITICAL NOTICE:** The strict runtime Server-Side Request Forgery (SSRF) protection described in previous versions of this design document (specifically `SafeHTTPTransport`) has been **REMOVED** from the `coreason-identity` library.

The library now relies on **infrastructure-level security controls** to prevent SSRF attacks.

## 2. Mechanism: Infrastructure Delegation

`IdentityManager` initializes a standard `httpx.AsyncClient` with basic timeout configurations. It does **NOT** enforce IP filtering, DNS pinning, or private network blocking at the application level.

```python
# src/coreason_identity/manager.py
self._client = httpx.AsyncClient(timeout=self.config.http_timeout)
```

### Required Infrastructure Controls

Since the library does not protect against SSRF, consumers **MUST** deploy this library in an environment with robust egress filtering. Recommended controls include:

1.  **Service Mesh (e.g., Istio, Linkerd):** Configure `ServiceEntry` and `EgressGateway` to whitelist only authorized OIDC provider domains (e.g., `*.auth0.com`, `cognito-idp.*.amazonaws.com`).
2.  **Network Policies (Kubernetes):** Restrict pod egress traffic to known external IPs or specific FQDNs.
3.  **Firewall / Security Groups:** Block outbound traffic to:
    *   Metadata services (e.g., `169.254.169.254`).
    *   Internal subnets (RFC 1918).
    *   Loopback (`127.0.0.0/8`).

## 3. Residual Risk

If deployed without these infrastructure controls, the library is vulnerable to SSRF attacks where a malicious user could configure a custom OIDC domain (if allowed by the application) to scan internal ports or access cloud metadata.

*   **Protocol Restriction:** The library strictly enforces `https://` for OIDC discovery, which mitigates some attacks against non-TLS internal services.
*   **Domain Validation:** `CoreasonVerifierConfig` enforces that the configured domain is a valid hostname and not a URL, preventing some injection attacks.

## 4. History

The `SafeHTTPTransport` mechanism was removed to simplify the library and delegate network security to the platform layer, consistent with modern "Zero Trust" networking principles where the network infrastructure enforces boundaries.
