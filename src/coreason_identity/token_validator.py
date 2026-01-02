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
TokenValidator component for validating JWTs.
"""

from typing import Any, Dict

from authlib.jose import JoseError, jwt
from authlib.jose.errors import (
    BadSignatureError,
    ExpiredTokenError,
    InvalidClaimError,
)

from coreason_identity.config import CoreasonIdentityConfig
from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InvalidAudienceError,
    SignatureVerificationError,
    TokenExpiredError,
)
from coreason_identity.oidc_provider import OIDCProvider


class TokenValidator:
    """
    Validates JWT signatures and claims.
    """

    def __init__(self, config: CoreasonIdentityConfig, oidc_provider: OIDCProvider) -> None:
        """
        Initialize the TokenValidator.

        Args:
            config: The configuration object containing domain and audience.
            oidc_provider: The OIDC provider to fetch JWKS from.
        """
        self.config = config
        self.oidc_provider = oidc_provider

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validates the given JWT.

        Args:
            token: The raw JWT string (without "Bearer " prefix).

        Returns:
            The validated claims dictionary.

        Raises:
            TokenExpiredError: If the token has expired.
            InvalidAudienceError: If the audience is invalid.
            SignatureVerificationError: If the signature is invalid.
            CoreasonIdentityError: For other validation errors.
        """
        try:
            # 1. Fetch JWKS
            jwks = self.oidc_provider.get_jwks()

            # 2. Decode and validate
            issuer = self.config.domain
            if not issuer.startswith("http"):
                issuer = f"https://{issuer}/"

            claims_options = {
                "iss": {"essential": True, "value": issuer},
                "aud": {"essential": True, "value": self.config.audience},
                "exp": {"essential": True},
            }

            claims = jwt.decode(token, jwks, claims_options=claims_options)
            claims.validate()

            return dict(claims)

        except ExpiredTokenError as e:
            raise TokenExpiredError(f"Token expired: {e}") from e
        except InvalidClaimError as e:
            if "aud" in str(e):
                raise InvalidAudienceError(f"Invalid audience: {e}") from e
            raise CoreasonIdentityError(f"Invalid claim: {e}") from e
        except BadSignatureError as e:
            raise SignatureVerificationError(f"Invalid signature: {e}") from e
        except JoseError as e:
            # Catch other authlib errors
            raise CoreasonIdentityError(f"Token validation failed: {e}") from e
        except Exception as e:
            raise CoreasonIdentityError(f"Unexpected error during token validation: {e}") from e
