# 012: Python Modernization (The 3.12 Directive)

**Status:** Active
**Driver:** Modernization & Type Safety
**Date:** 2025-05-15

## Context

The `coreason-identity` package is a foundational component of the CoReason platform. As the Python ecosystem evolves, we must adopt modern standards to ensure maintainability, type safety, and developer ergonomics.

Previously, the codebase supported Python 3.11, necessitating verbose type hints (`Optional[str]`, `Union[str, int]`) and preventing the use of newer Pydantic/dataclass features like `kw_only=True` (cleanly) or `type` alias syntax.

## Decision

We are enforcing a **strict minimum version of Python 3.12** for this package.

### 1. Dropping Python < 3.12
We explicitly drop support for Python 3.8, 3.9, 3.10, and 3.11. This is a breaking change (SemVer Major/Minor bump required).

### 2. Modern Type Syntax
We adopt the new type union operator (`|`) introduced in PEP 604 (Python 3.10) and the standard collection generics (PEP 585, Python 3.9) as the **mandatory standard**.

*   **Old:** `Optional[str]`, `Union[int, float]`, `List[str]`, `Dict[str, Any]`
*   **New:** `str | None`, `int | float`, `list[str]`, `dict[str, Any]`

This simplifies docstrings and function signatures, making the API surface cleaner and more readable.

### 3. Pydantic & Dataclasses
The Python 3.12+ requirement allows us to leverage:
*   `@dataclass(kw_only=True)`: Enforcing keyword-only arguments for data structures without hacks.
*   Pydantic V2 performance optimizations tailored for newer Python versions.

## Migration Strategy

1.  **Project Metadata:** Update `requires-python` in `pyproject.toml` to `>=3.12`.
2.  **Codebase Refactor:** Systematically replace all `typing` imports (`Optional`, `Union`, `List`, `Dict`) with native types.
3.  **Documentation:** Update all docstrings to reflect the new syntax.

## Testing Implications

Tests must verify that the package environment is indeed running on Python 3.12+ (e.g., via `sys.version_info`).
Tests should also cover "modern" usage patterns (e.g., verifying that a Pydantic model defined with `str | None` validation works correctly at runtime) to ensure no regressions in the underlying libraries (Pydantic/Authlib) on the new Python version.
