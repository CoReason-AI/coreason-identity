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

import anyio
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

from coreason_identity.exceptions import (
    CoreasonIdentityError,
    InvalidAudienceError,
    InvalidTokenError,
    SignatureVerificationError,
    TokenExpiredError,
)
from coreason_identity.oidc_provider import OIDCProviderAsync
from coreason_identity.utils.logger import logger

tracer = trace.get_tracer(__name__)


class TokenValidatorAsync:
    """
    Validates JWT tokens against the IdP's JWKS and standard claims (Async).
    """

    def __init__(self, oidc_provider: OIDCProviderAsync, audience: str, issuer: Optional[str] = None) -> None:
        """
        Initialize the TokenValidatorAsync.

        Args:
            oidc_provider: The OIDCProviderAsync instance to fetch JWKS.
            audience: The expected audience (aud) claim.
            issuer: The expected issuer (iss) claim.
        """
        self.oidc_provider = oidc_provider
        self.audience = audience
        self.issuer = issuer
        # Use a specific JsonWebToken instance to enforce RS256 and reject 'none'
        self.jwt = JsonWebToken(["RS256"])

    async def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validates the JWT signature and claims.
        """
        with tracer.start_as_current_span("validate_token") as span:
            # Sanitize input
            token = token.strip()

            # Define claim options
            claims_options = {
                "exp": {"essential": True},
                "aud": {"essential": True, "value": self.audience},
            }
            if self.issuer:
                claims_options["iss"] = {"essential": True, "value": self.issuer}

            def _decode(jwks: Dict[str, Any]) -> Any:
                # This is CPU bound
                claims = self.jwt.decode(token, jwks, claims_options=claims_options)
                claims.validate()
                return claims

            try:
                # Fetch JWKS (cached)
                jwks = await self.oidc_provider.get_jwks()

                try:
                    # Offload crypto to thread
                    claims = await anyio.to_thread.run_sync(_decode, jwks)
                except (ValueError, BadSignatureError):
                    # If key is missing or signature is bad (potential key rotation), try refreshing keys
                    logger.info("Validation failed with cached keys, refreshing JWKS and retrying...")
                    span.add_event("refreshing_jwks")
                    jwks = await self.oidc_provider.get_jwks(force_refresh=True)
                    # Offload crypto to thread
                    claims = await anyio.to_thread.run_sync(_decode, jwks)

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


class TokenValidator:
    """
    Sync Facade for TokenValidatorAsync.
    """

    def __init__(self, oidc_provider: Any, audience: str, issuer: Optional[str] = None) -> None:
        """
        Initialize the TokenValidator.

        Args:
            oidc_provider: The OIDCProvider (Sync) or OIDCProviderAsync instance.
            audience: The expected audience (aud) claim.
            issuer: The expected issuer (iss) claim.
        """
        # Handle Sync Facade vs Async instance
        if hasattr(oidc_provider, "_async"):
            oidc_async = oidc_provider._async
            self._oidc_provider_sync = oidc_provider
        else:
            oidc_async = oidc_provider
            self._oidc_provider_sync = None

        self._async = TokenValidatorAsync(oidc_async, audience, issuer)

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validates the JWT signature and claims.
        """
        # If wrapped OIDC provider has an active portal, run on that portal
        if self._oidc_provider_sync and getattr(self._oidc_provider_sync, "_portal", None):
             return self._oidc_provider_sync._portal.call(self._async.validate_token, token)

        # Fallback: run in a new loop (stateless execution)
        return anyio.run(self._async.validate_token, token)
