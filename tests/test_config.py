# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

import pytest
from pydantic import ValidationError

from coreason_identity.config import CoreasonIdentityConfig


def test_config_initialization(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COREASON_AUTH_DOMAIN", "example.com")
    monkeypatch.setenv("COREASON_AUTH_AUDIENCE", "my-audience")

    config = CoreasonIdentityConfig()  # type: ignore[call-arg]
    assert config.domain == "example.com"
    assert config.audience == "my-audience"


def test_config_initialization_with_args() -> None:
    config = CoreasonIdentityConfig(domain="test.com", audience="test-aud")
    assert config.domain == "test.com"
    assert config.audience == "test-aud"


def test_config_missing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("COREASON_AUTH_DOMAIN", raising=False)
    monkeypatch.delenv("COREASON_AUTH_AUDIENCE", raising=False)

    with pytest.raises(ValidationError):
        CoreasonIdentityConfig()  # type: ignore[call-arg]
