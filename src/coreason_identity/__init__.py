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
Decoupled authentication middleware, abstracting OIDC and OAuth2 protocols from the main application.
"""

__version__ = "0.3.0"
__author__ = "Gowtham A Rao"
__email__ = "gowtham.rao@coreason.ai"

from .config import CoreasonIdentityConfig
from .device_flow_client import DeviceFlowClient, DeviceFlowClientAsync
from .exceptions import InvalidTokenError
from .manager import IdentityManager, IdentityManagerAsync
from .models import UserContext
from .oidc_provider import OIDCProvider, OIDCProviderAsync
from .validator import TokenValidator, TokenValidatorAsync

__all__ = [
    "CoreasonIdentityConfig",
    "DeviceFlowClient",
    "DeviceFlowClientAsync",
    "IdentityManager",
    "IdentityManagerAsync",
    "InvalidTokenError",
    "OIDCProvider",
    "OIDCProviderAsync",
    "TokenValidator",
    "TokenValidatorAsync",
    "UserContext",
]
