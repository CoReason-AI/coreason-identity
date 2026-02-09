from pydantic import SecretStr

from coreason_identity.models import CoreasonGroup, CoreasonScope, UserContext


def test_user_context_repr_security() -> None:
    """
    Test that the string representation of UserContext handles sensitive fields securely.
    """
    secret_value = "super_secret_token_value"
    user = UserContext(
        user_id="user123",
        email="test@example.com",
        groups=[CoreasonGroup.ADMIN],
        scopes=[CoreasonScope.OPENID],
        downstream_token=SecretStr(secret_value),
    )

    repr_str = repr(user)
    str_str = str(user)

    # Check that sensitive data is NOT present
    assert secret_value not in repr_str
    assert secret_value not in str_str

    # Check that PII fields are redacted
    assert "user123" not in repr_str
    assert "test@example.com" not in repr_str
    assert "<REDACTED>" in repr_str

    # Check that group/scope data is present (considered non-PII metadata)
    assert "admin" in repr_str.lower() or "ADMIN" in repr_str
    assert "openid" in repr_str.lower() or "OPENID" in repr_str

    # Check structure resembles class signature
    assert repr_str.startswith("UserContext(")
    assert repr_str.endswith(")")
