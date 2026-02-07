from pydantic import BaseModel, ConfigDict, Field


class ComplexModernModel(BaseModel):
    """
    Complex Case: A deeply nested model using modern Python syntax exclusively.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # PEP 604
    id: str | int
    # PEP 585
    metadata: dict[str, str | int | float | None]
    tags: set[str]
    history: list[tuple[str, int]] = Field(default_factory=list)

    def compute_summary(self) -> str | None:
        if not self.history:
            return None
        return f"History length: {len(self.history)}"


def test_complex_model_valid() -> None:
    """
    Complex Case: Validate correct instantiation and field typing using new syntax.
    """
    data = {
        "id": "user-123",
        "metadata": {"score": 98.5, "category": "A", "retry_count": 3, "archived": None},
        "tags": {"active", "verified"},
        "history": [("login", 1620000000), ("logout", 1620003600)],
    }

    model = ComplexModernModel(**data)
    assert model.id == "user-123"
    assert model.metadata["score"] == 98.5
    assert model.compute_summary() == "History length: 2"
    assert isinstance(model.tags, set)
    assert isinstance(model.history, list)


def test_complex_model_redundant_check() -> None:
    """
    Complex Case (Redundant): Similar to above but with different data permutation
    to stress test Pydantic's handling of the new union types.
    """
    data_alt = {
        "id": 999,  # Union allows int
        "metadata": {"empty": None},
        "tags": set(),
        "history": [],
    }
    model = ComplexModernModel(**data_alt)
    assert model.id == 999
    assert model.metadata["empty"] is None
    assert model.tags == set()
    assert model.compute_summary() is None


class RecursiveModernModel(BaseModel):
    """
    Complex Case: Recursive model definition using string forward refs but modern syntax.
    Note: self-referencing types usually require `from __future__ import annotations` or string refs.
    But in 3.10+ `|` works for strings too if quoted or if future imported.
    Let's test if Pydantic handles `RecursiveModernModel | None` without quotes in 3.12.
    """

    name: str
    # Using string forward ref with pipe syntax inside the string is tricky.
    # Pydantic supports `child: "RecursiveModernModel | None"`.
    # Let's try native syntax if possible, but without future import, the class name isn't bound yet.
    # So we use string.
    child: "RecursiveModernModel | None" = None


def test_recursive_modern_syntax() -> None:
    """
    Complex Case: Recursive Pydantic model with modern syntax forward refs.
    """
    leaf = RecursiveModernModel(name="leaf")
    root = RecursiveModernModel(name="root", child=leaf)

    assert root.child is not None
    assert root.child.name == "leaf"
    assert root.child.child is None
