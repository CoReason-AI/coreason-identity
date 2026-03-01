# 🤖 AUTONOMOUS AGENT DIRECTIVE: COREASON-IDENTITY

## 1. The Domain
`coreason-identity` is the **Active Middleware Engine** of the Coreason ecosystem.
Unlike `coreason-manifest` (which is a pure, passive data library), this repository is responsible for **Active Verification, Network Communication, and Cryptography**.

## 2. Supreme Architectural Laws
1. **The Shared Kernel Mandate:** You are STRICTLY FORBIDDEN from defining new Identity data schemas (e.g., User contexts, Passports, Delegation contracts). You must import and utilize `IdentityPassport` and related primitives exclusively from `coreason_manifest.core.common.identity`.
2. **Active Execution Only:** Your job is to fetch JWKS endpoints, verify Post-Quantum (PQC) and standard signatures, synthesize passports, and evaluate temporal/compute boundaries.
3. **Asynchronous First:** All network calls (JWKS fetching, CAEP pub/sub) MUST be asynchronous using `httpx` or native `asyncio` primitives. Blocking the event loop is a critical failure.
4. **Zero-Trust Failsafe:** Any exception during validation must result in a mathematically hard failure. We default to `DENY`.

## 3. Toolchain
- **Package Manager:** `uv`
- **Linting & Formatting:** `uv run ruff check .` / `uv run ruff format .`
- **Typing:** `uv run mypy src/ tests/` (Zero errors tolerated).
- **Testing:** `uv run pytest`