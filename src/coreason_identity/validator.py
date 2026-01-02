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
TokenValidator component for validating JWT signatures and claims.
"""

from typing import Any, Dict, Optional

from authlib.jose import jwt
from authlib.jose.errors import (
    BadSignatureError,
    ExpiredTokenError,
    InvalidClaimError,
    JoseError,
    MissingClaimError,
)

from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InvalidAudienceError,
    SignatureVerificationError,
    TokenExpiredError,
)
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.utils.logger import logger


class TokenValidator:
    """
    Validates JWT tokens against the IdP's JWKS and standard claims.
    """

    def __init__(self, oidc_provider: OIDCProvider, audience: str, issuer: Optional[str] = None) -> None:
        """
        Initialize the TokenValidator.

        Args:
            oidc_provider: The OIDCProvider instance to fetch JWKS.
            audience: The expected audience (aud) claim.
            issuer: The expected issuer (iss) claim.
        """
        self.oidc_provider = oidc_provider
        self.audience = audience
        self.issuer = issuer

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validates the JWT signature and claims.

        Args:
            token: The raw Bearer token string.

        Returns:
            The validated claims dictionary.

        Raises:
            TokenExpiredError: If the token has expired.
            InvalidAudienceError: If the audience is invalid.
            SignatureVerificationError: If the signature is invalid.
            CoreasonIdentityError: For other validation errors.
        """
        try:
            # Fetch JWKS
            jwks = self.oidc_provider.get_jwks()

            # Define claim options
            claims_options = {
                "exp": {"essential": True},
                "aud": {"essential": True, "value": self.audience},
            }
            if self.issuer:
                claims_options["iss"] = {"essential": True, "value": self.issuer}

            # Decode and validate
            # authlib.jose.jwt.decode handles signature verification and claim validation
            claims = jwt.decode(token, jwks, claims_options=claims_options)
            claims.validate()

            payload = dict(claims)

            # Log success
            user_sub = payload.get("sub", "unknown")
            logger.info(f"Token validated for user {user_sub}")

            return payload

        except ExpiredTokenError as e:
            logger.warning(f"Validation failed: Token expired - {e}")
            raise TokenExpiredError(f"Token has expired: {e}") from e
        except InvalidClaimError as e:
            logger.warning(f"Validation failed: Invalid claim - {e}")
            if "aud" in str(e):
                raise InvalidAudienceError(f"Invalid audience: {e}") from e
            raise CoreasonIdentityError(f"Invalid claim: {e}") from e
        except MissingClaimError as e:
            logger.warning(f"Validation failed: Missing claim - {e}")
            raise CoreasonIdentityError(f"Missing claim: {e}") from e
        except BadSignatureError as e:
            logger.error(f"Validation failed: Bad signature - {e}")
            raise SignatureVerificationError(f"Invalid signature: {e}") from e
        except JoseError as e:
            logger.error(f"Validation failed: JOSE error - {e}")
            raise CoreasonIdentityError(f"Token validation failed: {e}") from e
        except Exception as e:
            logger.exception("Unexpected error during token validation")
            raise CoreasonIdentityError(f"Unexpected error during token validation: {e}") from e
