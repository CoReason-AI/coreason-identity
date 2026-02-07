# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import sys
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError


def test_python_version_is_modern():
    """
    Edge Case: Verify that the runtime environment is strictly Python 3.12+.
    This ensures that the package constraint is respected by the test runner.
    """
    assert sys.version_info >= (3, 12), f"Tests are running on old Python: {sys.version}"


def test_modern_union_syntax_runtime():
    """
    Edge Case: Verify that the `|` syntax works for `isinstance` checks at runtime.
    This was introduced in 3.10, but mandatory for our 3.12+ strategy.
    """
    assert isinstance(None, str | None)
    assert isinstance("hello", str | None)
    assert isinstance(123, int | float)
    assert isinstance(123.45, int | float)

    # Negative cases
    assert not isinstance(123, str | None)
    assert not isinstance(None, int | float)


def test_generic_alias_runtime():
    """
    Edge Case: Verify that standard collections support subscripting at runtime.
    (PEP 585).
    """
    # This syntax `list[str]` is valid as a type hint, but at runtime:
    # `list[str]` returns a GenericAlias.

    my_list_type = list[str]
    assert str(my_list_type) == "list[str]"

    my_dict_type = dict[str, Any]
    assert str(my_dict_type) == "dict[str, typing.Any]" or "dict[str, Any]" in str(my_dict_type)


def test_dataclass_kw_only_behavior_in_pydantic():
    """
    Edge Case: Verify modern Pydantic usage (v2) which leverages modern python features.
    Although `kw_only` is a dataclass feature, Pydantic ConfigDict supports similar strictness.
    We test that we can define a model using Python 3.12 syntax.
    """
    class ModernModel(BaseModel):
        # Python 3.10+ syntax for unions
        name: str | None = None
        # PEP 585 generics
        tags: list[str] = []

        model_config = ConfigDict(frozen=True)

    m = ModernModel(name="test", tags=["a", "b"])
    assert m.name == "test"
    assert m.tags == ["a", "b"]

    # Verify strict typing enforcement by Pydantic
    with pytest.raises(ValidationError):
        ModernModel(tags="not-a-list")  # type: ignore


def test_new_union_operator_in_class_definition():
    """
    Edge Case: Define a class using `|` in methods and verify it parses and runs.
    This tests the interpreter's parser capabilities.
    """
    class ModernClass:
        def process(self, value: int | str) -> list[str] | None:
            if isinstance(value, int):
                return [str(value)]
            return None

    obj = ModernClass()
    assert obj.process(10) == ["10"]
    assert obj.process("s") is None
