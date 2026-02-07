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
Entry point for the coreason-identity package.
Demonstrates usage of the IdentityManager for both token validation and device flow.
"""

import sys  # pragma: no cover

from coreason_identity.config import CoreasonIdentityConfig  # pragma: no cover
from coreason_identity.exceptions import CoreasonIdentityError  # pragma: no cover
from coreason_identity.manager import IdentityManager  # pragma: no cover


def main() -> None:  # pragma: no cover
    """
    Main entry point for manual verification and demonstration.
    """
    print("Coreason Identity - The Bouncer")
    print("-------------------------------")

    # 1. Configuration (Mock or Env)
    # In a real app, these would come from env vars.
    # For this demo/check, we use placeholders or expect env vars to be set.
    try:
        config = CoreasonIdentityConfig(
            domain="auth.example.com",  # Replace with real domain for live test
            audience="api://coreason",
            client_id="demo-client-id",
        )
    except Exception as e:
        print(f"Configuration Error: {e}")
        print("Please set COREASON_AUTH_DOMAIN and COREASON_AUTH_AUDIENCE env vars.")
        sys.exit(1)

    identity = IdentityManager(config)
    print(f"Initialized IdentityManager for domain: {config.domain}")

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "validate":
            if len(sys.argv) < 3:
                print("Usage: python -m coreason_identity.main validate <token>")
                sys.exit(1)
            token = sys.argv[2]
            print(f"\nValidating token: {token[:10]}...")
            try:
                # Expecting raw token or "Bearer <token>"
                header = token if token.startswith("Bearer ") else f"Bearer {token}"
                user = identity.validate_token(header)
                print("\nSUCCESS: Token Validated")
                print(f"User ID: {user.user_id}")
                print(f"Email:   {user.email}")
                print(f"Groups:  {user.groups}")
                print(f"Scopes:  {user.scopes}")
                print(f"Claims:  {user.claims}")
            except CoreasonIdentityError as e:
                print(f"\nFAILURE: Validation Failed - {e}")

        elif command == "login":
            print("\nInitiating Device Flow Login...")
            try:
                flow = identity.start_device_login()
                print(f"\nPlease visit: {flow.verification_uri}")
                print(f"And enter code: {flow.user_code}")
                print("\nWaiting for approval...")
                tokens = identity.await_device_token(flow)
                print("\nSUCCESS: Login Complete")
                print(f"Access Token:  {tokens.access_token[:20]}...")
                print(f"Refresh Token: {tokens.refresh_token[:20] if tokens.refresh_token else 'N/A'}...")
            except CoreasonIdentityError as e:
                print(f"\nFAILURE: Login Failed - {e}")

        else:
            print(f"Unknown command: {command}")
            print("Available commands: validate, login")
    else:
        print("\nNo command provided.")
        print("Usage:")
        print("  python -m coreason_identity.main validate <token>")
        print("  python -m coreason_identity.main login")


if __name__ == "__main__":  # pragma: no cover
    main()
