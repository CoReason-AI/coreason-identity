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
Data models for the coreason-identity package.
"""

from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


class UserContext(BaseModel):
    """
    Standardized User Context object to be available throughout the middleware stack.
    """

    sub: str
    email: EmailStr
    project_context: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
