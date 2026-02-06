# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_identity

"""
Coreason Identity SDK
"""

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InsufficientPermissionsError,
    InvalidAudienceError,
    InvalidTokenError,
    SignatureVerificationError,
    TokenExpiredError,
)
from coreason_identity.manager import IdentityManager, IdentityManagerAsync
from coreason_identity.models import DeviceFlowResponse, TokenResponse, UserContext

__version__ = "0.5.0"
__author__ = "Gowtham A Rao"
__email__ = "gowtham.rao@coreason.ai"

__all__ = [
    "CoreasonIdentityConfig",
    "CoreasonIdentityError",
    "DeviceFlowResponse",
    "IdentityManager",
    "IdentityManagerAsync",
    "InsufficientPermissionsError",
    "InvalidAudienceError",
    "InvalidTokenError",
    "SignatureVerificationError",
    "TokenExpiredError",
    "TokenResponse",
    "UserContext",
]
