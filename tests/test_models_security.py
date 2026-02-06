import pytest
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
        scopes=["read"],
        downstream_token=SecretStr("secret"),
        claims={
            "phone_number": "+1-555-0199",
            "address": sensitive_value,
            "other": "data"
        },
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
    assert "read" in repr_str

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
