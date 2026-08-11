"""Thin Authentik API wrapper: auth, retry only. No business logic, no
mapping — see .chief/project.md's Client -> Mapper -> Migrator layering.
"""

from __future__ import annotations

import httpx

from kc2ak.http import build_client, request_with_retry
from kc2ak.redact import redact, register_secret


class AuthentikAuthError(Exception):
    """Raised when Authentik rejects the configured token."""


class AuthentikClient:
    def __init__(
        self, base_url: str, token: str, transport: httpx.BaseTransport | None = None
    ) -> None:
        # Registered here too (not just in config.py) so the token is
        # redacted even if the caller constructed this client directly.
        register_secret(token)
        self._client = build_client(
            base_url.rstrip("/"), headers={"Authorization": f"Bearer {token}"}, transport=transport
        )

    def close(self) -> None:
        self._client.close()

    def authenticate(self) -> None:
        """Verify the configured token is accepted."""
        response = request_with_retry(self._client, "GET", "/api/v3/core/users/me/")
        if response.status_code != 200:
            raise AuthentikAuthError(
                redact(f"Authentik rejected credentials: {response.status_code} {response.text}")
            )

    def flow_exists(self, slug: str) -> bool:
        """Look up a flow by slug on the target instance.

        invalidation_flow lives on authentik's Provider base model, not
        OAuth2Provider, and was added in a later release than the rest of the
        fields this tool writes — rather than assume a version, this checks
        the live instance for whatever flow slug is passed in, the same way
        authorization_flow is checked.
        """
        response = request_with_retry(
            self._client, "GET", "/api/v3/flows/instances/", params={"slug": slug}
        )
        response.raise_for_status()
        results: list[object] = response.json().get("results", [])
        return bool(results)
