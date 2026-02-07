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
from typing import Any

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
        issuer (str | None): The expected issuer claim.
    """

    def __init__(
        self,
        oidc_provider: OIDCProvider,
        audience: str,
        issuer: str | None = None,
        pii_salt: SecretStr | None = None,
    ) -> None:
        """
        Initialize the TokenValidator.

        Args:
            oidc_provider: The OIDCProvider instance to fetch JWKS.
            audience: The expected audience (aud) claim.
            issuer: The expected issuer (iss) claim. If None, it will be fetched dynamically from OIDCProvider.
            pii_salt: Salt for anonymizing PII. Defaults to unsafe static salt if not provided.
        """
        self.oidc_provider = oidc_provider
        self.audience = audience
        self.issuer = issuer
        self.pii_salt = pii_salt or SecretStr("coreason-unsafe-default-salt")
        # Use a specific JsonWebToken instance to enforce RS256 and reject 'none'
        self.jwt = JsonWebToken(["RS256"])

    def _anonymize(self, value: str) -> str:
        """
        Anonymizes a value using HMAC-SHA256 with the configured salt.

        Args:
            value: The value to anonymize.

        Returns:
            The anonymized hex digest.
        """
        return hmac.new(
            self.pii_salt.get_secret_value().encode("utf-8"),
            value.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    async def validate_token(self, token: str) -> dict[str, Any]:
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

                # Define claim options factory
                def get_claims_options(iss: str) -> dict[str, Any]:
                    return {
                        "exp": {"essential": True},
                        "aud": {"essential": True, "value": self.audience},
                        "iss": {"essential": True, "value": iss},
                    }

                # Ensure issuer is not None before passing to get_claims_options
                # self.issuer should be populated if initialized correctly,
                # otherwise we fetch it or raise.
                # However, type hint says str | None.
                # If dynamic discovery is disabled (implicit in current design), issuer MUST be present.
                # We can fallback to fetching if None, or assume it's set if we are enforcing it.
                # Given previous context, we might want to fetch it if missing.
                # But Config validator sets default.
                # So we can assert or handle it.
                # Let's use the fetched/configured issuer.

                # For MyPy, we need to ensure it's not None.
                # If we are here, we might have skipped dynamic fetch if self.issuer was set.
                # If self.issuer is None, we need to handle it.

                final_issuer = self.issuer
                if not final_issuer:
                    final_issuer = await self.oidc_provider.get_issuer()

                claims_options = get_claims_options(final_issuer)

                def _decode(jwks_data: dict[str, Any], opts: dict[str, Any]) -> Any:
                    claims = self.jwt.decode(token, jwks_data, claims_options=opts)  # type: ignore[call-overload]
                    claims.validate()
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
                span.set_attribute("user.id", user_hash)
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
