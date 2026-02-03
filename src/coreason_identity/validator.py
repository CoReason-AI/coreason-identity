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

import hashlib
from typing import Any, Dict, Optional

from authlib.jose import JsonWebToken
from authlib.jose.errors import (
    BadSignatureError,
    ExpiredTokenError,
    InvalidClaimError,
    JoseError,
    MissingClaimError,
)
from authlib.jose.util import extract_header
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InvalidAudienceError,
    InvalidTokenError,
    SignatureVerificationError,
    TokenExpiredError,
)
from coreason_identity.oidc_provider import OIDCProvider
from coreason_identity.utils.logger import logger

tracer = trace.get_tracer(__name__)


class TokenValidator:
    """
    Validates JWT tokens against the IdP's JWKS and standard claims.

    Attributes:
        oidc_provider (OIDCProvider): The OIDCProvider instance.
        audience (str): The expected audience claim.
        issuer (Optional[str]): The expected issuer claim.
    """

    def __init__(self, oidc_provider: OIDCProvider, audience: str, issuer: Optional[str] = None) -> None:
        """
        Initialize the TokenValidator.

        Args:
            oidc_provider: The OIDCProvider instance to fetch JWKS.
            audience: The expected audience (aud) claim.
            issuer: The expected issuer (iss) claim. If None, it will be fetched dynamically from OIDCProvider.
        """
        self.oidc_provider = oidc_provider
        self.audience = audience
        self.issuer = issuer
        # Use a specific JsonWebToken instance to enforce RS256 and reject 'none'
        self.jwt = JsonWebToken(["RS256"])

    def _should_refresh_jwks(self, token: str, jwks: Dict[str, Any], exception: Exception) -> bool:
        """
        Determines whether to trigger a JWKS refresh based on the token header and error.
        Implements Smart Refresh / DoS Protection.
        """
        # Only consider refresh for signature/value errors (potential key rotation)
        if not isinstance(exception, (ValueError, BadSignatureError)):
            return False

        try:
            # Extract the header segment (first part before the dot)
            parts = token.split(".")
            # str.split always returns at least one element.
            header_segment = parts[0].encode("utf-8")
            header = extract_header(header_segment, None)
            kid = header.get("kid")

            # If no kid, we can't do smart check, but RS256 usually requires kid.
            # If kid is present, check if we have it.
            if kid:
                known_keys = [k.get("kid") for k in jwks.get("keys", [])]
                if kid not in known_keys:
                    logger.info(f"Token has unknown kid '{kid}'. Triggering refresh.")
                    return True
                else:
                    logger.warning(
                        f"Token has known kid '{kid}' but validation failed ({type(exception).__name__}). "
                        "Not refreshing."
                    )
                    return False
            else:
                # No kid in header, assume we might need refresh if rotation happened without kid (unlikely for OIDC)
                return True

        except Exception:
            # If we can't parse header, token is garbage. Don't refresh.
            logger.warning("Failed to parse token header. Not refreshing.")
            return False

    async def validate_token(self, token: str) -> Dict[str, Any]:
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
            InvalidTokenError: If claims are missing or invalid.
            CoreasonIdentityError: For unexpected errors.
        """
        with tracer.start_as_current_span("validate_token") as span:
            # Sanitize input
            token = token.strip()

            try:
                # Fetch JWKS (cached)
                # This ensures OIDC config is also fetched/cached
                jwks = await self.oidc_provider.get_jwks()

                # Determine expected issuer
                expected_issuer = self.issuer
                if not expected_issuer:
                    expected_issuer = await self.oidc_provider.get_issuer()

                # Define claim options factory
                def get_claims_options(iss: str) -> Dict[str, Any]:
                    return {
                        "exp": {"essential": True},
                        "aud": {"essential": True, "value": self.audience},
                        "iss": {"essential": True, "value": iss},
                    }

                claims_options = get_claims_options(expected_issuer)

                def _decode(jwks_data: Dict[str, Any], opts: Dict[str, Any]) -> Any:
                    claims = self.jwt.decode(token, jwks_data, claims_options=opts)
                    claims.validate()
                    return claims

                try:
                    claims = _decode(jwks, claims_options)
                except (ValueError, BadSignatureError) as e:
                    # DoS Protection / Smart Refresh check
                    if self._should_refresh_jwks(token, jwks, e):
                        logger.info(
                            "Validation failed with cached keys and unknown kid, refreshing JWKS and retrying..."
                        )
                        span.add_event("refreshing_jwks")
                        # force_refresh=True will now respect the debounce interval in OIDCProvider
                        jwks = await self.oidc_provider.get_jwks(force_refresh=True)

                        # Update issuer if dynamic
                        if not self.issuer:
                            expected_issuer = await self.oidc_provider.get_issuer()
                            claims_options = get_claims_options(expected_issuer)

                        claims = _decode(jwks, claims_options)
                    else:
                        raise

                payload = dict(claims)

                # Log success
                user_sub = payload.get("sub", "unknown")
                # Hash the user ID for strict privacy logging
                user_hash = hashlib.sha256(str(user_sub).encode("utf-8")).hexdigest()
                logger.info(f"Token validated for user {user_hash}")

                # Set span attributes
                span.set_attribute("user.id", str(user_sub))
                span.set_status(Status(StatusCode.OK))

                return payload

            except ExpiredTokenError as e:
                logger.warning(f"Validation failed: Token expired - {e}")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise TokenExpiredError(f"Token has expired: {e}") from e
            except InvalidClaimError as e:
                logger.warning(f"Validation failed: Invalid claim - {e}")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                if "aud" in str(e):
                    raise InvalidAudienceError(f"Invalid audience: {e}") from e
                # Wrap generic invalid claims as InvalidTokenError, not base error
                raise InvalidTokenError(f"Invalid claim: {e}") from e
            except MissingClaimError as e:
                logger.warning(f"Validation failed: Missing claim - {e}")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                # Wrap missing claims as InvalidTokenError
                raise InvalidTokenError(f"Missing claim: {e}") from e
            except BadSignatureError as e:
                logger.error(f"Validation failed: Bad signature - {e}")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise SignatureVerificationError(f"Invalid signature: {e}") from e
            except JoseError as e:
                logger.error(f"Validation failed: JOSE error - {e}")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                # Generic JOSE error implies invalid token
                raise InvalidTokenError(f"Token validation failed: {e}") from e
            except ValueError as e:
                # Authlib raises ValueError for "Invalid JSON Web Key Set" or "kid" not found sometimes
                logger.error(f"Validation failed: Value error (likely key missing) - {e}")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise SignatureVerificationError(f"Invalid signature or key not found: {e}") from e
            except Exception as e:
                logger.exception("Unexpected error during token validation")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise CoreasonIdentityError(f"Unexpected error during token validation: {e}") from e
