from typing import Any

from pydantic import SecretStr

from coreason_identity.models import UserContext


def test_user_context_repr_redaction() -> None:
    """
    Test that the string representation of UserContext redacts sensitive claims.
    """
    sensitive_value = "123 Secret Ln"
    user = UserContext(
        user_id="user123",
        email="test@example.com",
        groups=["admin"],
        scopes=["openid"],
        downstream_token=SecretStr("secret"),
        claims={"phone_number": "+1-555-0199", "address": sensitive_value, "other": "data"},
    )

    repr_str = repr(user)
    str_str = str(user)

    # Check that sensitive data is NOT present
    assert sensitive_value not in repr_str
    assert sensitive_value not in str_str
    assert "+1-555-0199" not in repr_str

    # Check for redaction marker
    assert "<REDACTED>" in repr_str
    assert "<REDACTED>" in str_str

    # Check that non-sensitive fields are present
    assert "user123" in repr_str
    assert "test@example.com" in repr_str
    assert "admin" in repr_str
    assert "openid" in repr_str

    # Check structure resembles class signature
    assert repr_str.startswith("UserContext(")
    assert repr_str.endswith(")")


def test_user_context_data_integrity() -> None:
    """
    Test that the actual claims data is still accessible programmatically.
    """
    claims_data = {"phone_number": "+1-555-0199", "address": "123 Secret Ln"}
    user = UserContext(
        user_id="user123",
        email="test@example.com",
        claims=claims_data,
    )

    # Assert that data is preserved
    assert user.claims == claims_data
    assert user.claims["address"] == "123 Secret Ln"


def test_user_context_repr_redaction_edge_cases() -> None:
    """
    Test edge cases for UserContext redaction:
    - Empty claims
    - None values in claims
    - Long strings
    - Special characters/Unicode
    """
    long_string = "a" * 1000
    unicode_val = "ユーザー"

    user = UserContext(
        user_id="edge_case_user",
        email="edge@example.com",
        claims={"empty": "", "none": None, "long": long_string, "unicode": unicode_val, "nested": {"key": "value"}},
    )

    repr_str = repr(user)

    # Assertions
    assert "<REDACTED>" in repr_str
    assert long_string not in repr_str
    assert unicode_val not in repr_str
    assert "value" not in repr_str  # Nested value should also be hidden
    assert "edge_case_user" in repr_str


def test_user_context_repr_redaction_complex_cases() -> None:
    """
    Test complex cases for UserContext redaction:
    - Nested dictionaries
    - Lists of dictionaries
    - Custom objects
    """

    class CustomObj:
        def __repr__(self) -> str:
            return "SensitiveCustomObj"

    complex_claims: dict[str, Any] = {
        "user_metadata": {"address": {"street": "123 Main", "zip": "90210"}, "preferences": ["email", "sms"]},
        "history": [{"login_ip": "1.2.3.4"}, {"login_ip": "5.6.7.8"}],
        "custom": CustomObj(),
    }

    user = UserContext(user_id="complex_user", email="complex@example.com", claims=complex_claims)

    repr_str = repr(user)

    # Assertions
    assert "<REDACTED>" in repr_str
    assert "123 Main" not in repr_str
    assert "90210" not in repr_str
    assert "1.2.3.4" not in repr_str
    assert "SensitiveCustomObj" not in repr_str

    # Verify integrity
    assert user.claims["user_metadata"]["address"]["street"] == "123 Main"
    assert isinstance(user.claims["custom"], CustomObj)
