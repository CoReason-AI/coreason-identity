# Package Modernization and Strictness Standards

## 1. Overview

In early 2026, the `coreason-identity` package underwent a significant modernization effort to align with state-of-the-art (SOTA) Python development practices. This initiative focused on enforcing strict static analysis, modernizing syntax, and ensuring robust type safety.

This document records the decisions and standards established during this process.

## 2. Strict Linting (Ruff)

We expanded the `ruff` configuration in `pyproject.toml` to include a broader set of rules. The goal is to enforce "one obvious way to do it" and catch potential bugs early.

### Enabled Rule Sets:
*   **UP (pyupgrade):** Enforces modern Python syntax (e.g., `list | dict` instead of `Union[list, dict]`, `super()` instead of `super(Class, self)`).
*   **SIM (flake8-simplify):** Simplifies code structure (e.g., merging nested `with` statements, removing redundant `pass`).
*   **RUF (Ruff-specific):** Advanced static analysis checks.
*   **ARG (flake8-unused-arguments):** Detects unused function arguments to keep signatures clean.
*   **C4 (flake8-comprehensions):** Enforces better list/dict comprehensions.
*   **PT (flake8-pytest-style):** Enforces best practices for `pytest` (e.g., explicit `@pytest.mark.asyncio()`).
*   **TCH (flake8-type-checking):** Moves type-only imports to `if TYPE_CHECKING:` blocks to reduce runtime overhead.
*   **PIE (flake8-pie):** Miscellaneous stylistic lints.
*   **RET (flake8-return):** Simplifies return logic (e.g., removing unnecessary `else` after `return`).

### Key Changes Implemented:
*   **Asyncio Markers:** All async tests must now use `@pytest.mark.asyncio()` (with parentheses) to satisfy `PT` rules.
*   **Union Types:** We use the modern `|` operator for type unions instead of `typing.Union`.
*   **Isinstance Checks:** We use `isinstance(x, A | B)` instead of `isinstance(x, (A, B))` where supported by tooling (though Ruff `UP038` is currently disabled/fixed if problematic in runtime).

## 3. Strict Type Checking (MyPy)

We tightened the `mypy` configuration to strict mode, removing the "escape hatch" of ignoring missing imports.

### Configuration Changes:
*   **`ignore_missing_imports = false`**: We now require type stubs for all dependencies.
*   **`warn_unused_ignores = true`**: Every `type: ignore` comment must be necessary; otherwise, it is flagged as an error.
*   **`warn_redundant_casts = true`**: Removing unnecessary casts.

### Dependencies:
To support strict typing for libraries that do not ship with inline types, we added:
*   **`types-authlib`**: Provides type stubs for the `Authlib` library, resolving strict check failures in `validator.py`.

## 4. Code Robustness

Refactoring for linting also improved code robustness:
*   **Context Managers:** Nested context managers are now combined (e.g., `with patch(...) as a, patch(...) as b:`), improving readability and reducing indentation depth.
*   **Explicit Returns:** Ensuring functions declared to return specific types do not implicitly return `None` or `Any`.

## 5. Future Maintenance

*   **New Code:** All new code submitted to this repository must adhere to these strict rules. The CI pipeline will fail if `ruff` or `mypy` report any issues.
*   **Overrides:** Use `type: ignore[code]` sparingly and only when strictly necessary (e.g., library overload limitations). Always include the specific error code.
