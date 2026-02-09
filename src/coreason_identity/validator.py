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
import hmac
from typing import Any, cast

from authlib.jose import JsonWebToken
from authlib.jose.errors import (
    BadSignatureError,
    ExpiredTokenError,
    InvalidClaimError,
    JoseError,
    MissingClaimError,
)
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from pydantic import SecretStr

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
        issuer (str): The expected issuer claim.
    """

    def __init__(
        self,
        oidc_provider: OIDCProvider,
        audience: str,
        issuer: str,
        pii_salt: SecretStr,
        allowed_algorithms: list[str],
        leeway: int = 0,
    ) -> None:
        """
        Initialize the TokenValidator.

        Args:
            oidc_provider: The OIDCProvider instance to fetch JWKS.
            audience: The expected audience (aud) claim.
            issuer: The expected issuer (iss) claim.
            pii_salt: Salt for anonymizing PII. REQUIRED.
            allowed_algorithms: List of allowed JWT signing algorithms. REQUIRED.
            leeway: Acceptable clock skew in seconds. Defaults to 0.
        """
        self.oidc_provider = oidc_provider
        self.audience = audience
        self.issuer = issuer
        self.pii_salt = pii_salt
        self.allowed_algorithms = allowed_algorithms
        self.leeway = leeway
        # Use a specific JsonWebToken instance to enforce allowed algorithms and reject others
        self.jwt = JsonWebToken(self.allowed_algorithms)

    def _anonymize(self, value: str) -> str:
        """
        Anonymizes a value using HMAC-SHA256 with the configured salt.

        Args:
            value: The value to anonymize.

        Returns:
            str: The anonymized hex digest.
        """
        return hmac.new(
            self.pii_salt.get_secret_value().encode("utf-8"),
            value.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    async def validate_token(self, token: str) -> dict[str, Any]:
        """
        Validates the JWT signature and claims.

        Emits an OpenTelemetry span `validate_token`.
        Sets attribute `user.id` (anonymized) on success.

        Args:
            token: The raw Bearer token string.

        Returns:
            dict[str, Any]: The validated claims dictionary.

        Raises:
            TokenExpiredError: If the token has expired.
            InvalidAudienceError: If the audience is invalid.
            SignatureVerificationError: If the signature is invalid or key is missing.
            InvalidTokenError: If claims are missing or invalid, or for general JOSE errors.
            CoreasonIdentityError: For unexpected errors.
        """
        with tracer.start_as_current_span("validate_token") as span:
            # Sanitize input
            token = token.strip()

            try:
                # Fetch JWKS (cached)
                # This ensures OIDC config is also fetched/cached
                jwks = await self.oidc_provider.get_jwks()

                # Define claim options factory
                def get_claims_options(iss: str) -> dict[str, Any]:
                    return {
                        "exp": {"essential": True, "leeway": self.leeway},
                        "nbf": {"essential": False, "leeway": self.leeway},
                        "aud": {"essential": True, "value": self.audience},
                        "iss": {"essential": True, "value": iss},
                    }

                claims_options = get_claims_options(self.issuer)

                def _decode(jwks_data: dict[str, Any], opts: dict[str, Any]) -> Any:
                    # Cast self.jwt to Any to bypass MyPy overload confusion or missing stubs
                    jwt_any = cast(Any, self.jwt)
                    claims = jwt_any.decode(token, jwks_data, claims_options=opts)
                    claims.validate(leeway=self.leeway)
                    return claims

                try:
                    claims = _decode(jwks, claims_options)
                except (ValueError, BadSignatureError):
                    # If key is missing or signature is bad (potential key rotation), try refreshing keys
                    logger.info("Validation failed with cached keys, refreshing JWKS and retrying...")
                    span.add_event("refreshing_jwks")
                    jwks = await self.oidc_provider.get_jwks(force_refresh=True)

                    claims = _decode(jwks, claims_options)

                payload = dict(claims)

                # Log success
                user_sub = payload.get("sub", "unknown")
                # Hash the user ID for strict privacy logging
                user_hash = self._anonymize(str(user_sub))
                logger.info(f"Token validated for user {user_hash}")

                # Set span attributes
                span.set_attribute("enduser.id", user_hash)
                span.set_status(Status(StatusCode.OK))

                return payload

            except ExpiredTokenError as e:
                # Token expired is safe to log, but we use exception formatting just in case
                logger.warning("Validation failed: Token expired", exc_info=True)
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise TokenExpiredError(f"Token has expired: {e}") from e
            except InvalidClaimError as e:
                logger.warning("Validation failed: Invalid claim", exc_info=True)
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                if "aud" in str(e):
                    raise InvalidAudienceError(f"Invalid audience: {e}") from e
                # Wrap generic invalid claims as InvalidTokenError, not base error
                raise InvalidTokenError(f"Invalid claim: {e}") from e
            except MissingClaimError as e:
                logger.warning("Validation failed: Missing claim", exc_info=True)
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                # Wrap missing claims as InvalidTokenError
                raise InvalidTokenError(f"Missing claim: {e}") from e
            except BadSignatureError as e:
                logger.error("Validation failed: Bad signature", exc_info=True)
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise SignatureVerificationError(f"Invalid signature: {e}") from e
            except JoseError as e:
                logger.error("Validation failed: JOSE error", exc_info=True)
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                # Generic JOSE error implies invalid token
                raise InvalidTokenError(f"Token validation failed: {e}") from e
            except ValueError as e:
                # Authlib can raise ValueError for "Invalid JSON Web Key Set" or "kid" not found.
                # We inspect the error message to see if it's a key/signature issue.
                err_str = str(e)
                if "Invalid JSON Web Key Set" in err_str or "kid" in err_str:
                    logger.error("Validation failed: Value error (likely key missing)", exc_info=True)
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, err_str))
                    raise SignatureVerificationError(f"Invalid signature or key not found: {e}") from e

                # Unexpected ValueError
                logger.error("Validation failed: Unexpected ValueError", exc_info=True)
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, err_str))
                raise CoreasonIdentityError(f"Unexpected ValueError during validation: {e}") from e
            except Exception as e:
                logger.exception("Unexpected error during token validation")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise CoreasonIdentityError(f"Unexpected error during token validation: {e}") from e
