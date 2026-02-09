import asyncio
import contextlib
import os
import sys

# Add src to path for running directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from anyio import create_task_group
from pydantic import SecretStr

from coreason_identity.config import CoreasonVerifierConfig
from coreason_identity.manager import IdentityManagerAsync


async def main() -> None:
    """
    Demonstrates Async OIDC Discovery using the modernized stack.
    Includes:
    - TaskGroup for concurrency
    - Stamina for retries (internal to OIDCProvider)
    - OpenTelemetry instrumentation (auto-applied in Manager)
    """
    print(">>> Starting Async OIDC Discovery Example")

    # Configuration with strict security defaults
    config = CoreasonVerifierConfig(
        domain="auth.example.com",
        audience="my-api",
        issuer="https://auth.example.com/",
        pii_salt=SecretStr("super-secret-salt-for-pii-hashing"),
        http_timeout=5.0,
        allowed_algorithms=["RS256"],
        unsafe_local_dev=True,  # Enabled for example to allow 'example.com' if needed
    )

    # Initialize the Manager (Async Context Manager)
    # This automatically instruments the internal httpx client with OpenTelemetry
    async with IdentityManagerAsync(config) as manager:
        print(f">>> Manager Initialized. Client: {type(manager._client).__name__}")

        # Demonstrate concurrency using TaskGroup
        # We trigger JWKS fetching and Issuer validation concurrently.
        # The internal 'stamina' retry logic will handle any transient network issues.
        print(">>> Starting concurrent OIDC tasks...")
        try:
            async with create_task_group() as tg:
                # Task 1: Force refresh JWKS
                print("    - Spawning JWKS fetch task")
                tg.start_soon(manager.oidc_provider.get_jwks, True)

                # Task 2: Get Issuer (fetches OIDC config if not cached)
                print("    - Spawning Issuer fetch task")
                tg.start_soon(manager.oidc_provider.get_issuer)

        except Exception as e:
            # In a real run without a server, this will fail after retries
            print(f">>> Expected failure (no real server): {e}")

        print(">>> Concurrent tasks finished.")


if __name__ == "__main__":
    # Use anyio.run or asyncio.run
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
