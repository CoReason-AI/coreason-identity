# Integration Guides: Security & Identity

This document outlines the standard "Security & Identity" sections that must be integrated into the architecture documentation of all dependent packages.

---

## coreason-api (The Gateway)

### Security & Identity
This service acts as the **Border Control**. It validates OIDC tokens and hydrates the `UserContext` passport before injecting it into the application context.

---

## coreason-maco (The State)

### Security & Identity
The Orchestrator persists the `UserContext` in the workflow state (Redis/Memory) so that long-running agents continue to act "On-Behalf-Of" the user who triggered the run. It sanitizes this context before emitting UI events.

---

## coreason-catalog (The Gatekeeper)

### Security & Identity
The Catalog uses `UserContext.groups` to enforce **Row-Level Security (RLS)**. Even if a resource exists, it is filtered out if the passport lacks the required group stamp.

---

## coreason-search (The Scout)

### Security & Identity
The Search engine does not store permissions. It accepts the `UserContext` and blindly passes it to the `Workspace`, ensuring that results are retrieved "Just-In-Time" using the user's own credentials.

---

## coreason-connect (The Hands)

### Security & Identity
This is the only service allowed to peek inside the `SecretStr`. It exchanges the `downstream_token` for a Microsoft Graph session to read emails or files exactly as the user.

---

## coreason-veritas (The Auditor)

### Security & Identity
The Audit system accepts `UserContext` to immutably log *who* performed an action (`user_id`), while explicitly excluding *how* they did it (redacting the token).

---

## coreason-cortex (The Brain)

### Security & Identity
The Cognitive Engine is trained to respect the "Identity Wall". It receives the `UserContext` but is instructed via System Prompt not to output it. It passes the context to tools via the MCP protocol.
