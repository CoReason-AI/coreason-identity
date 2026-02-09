from typing import Any

from pydantic import SecretStr

from coreason_identity.models import UserContext, CoreasonGroup, CoreasonScope


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

    # Check that non-sensitive fields are present
    assert "user123" in repr_str
    assert "test@example.com" in repr_str
    assert "admin" in repr_str
    assert "openid" in repr_str

    # Check structure resembles class signature
    assert repr_str.startswith("UserContext(")
    assert repr_str.endswith(")")
