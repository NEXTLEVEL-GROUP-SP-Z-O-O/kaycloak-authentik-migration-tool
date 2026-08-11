"""Thin Keycloak Admin API wrapper: auth, pagination, retry only.

No business logic, no mapping — see .chief/project.md's Client -> Mapper ->
Migrator layering.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx

from kc2ak.http import build_client, request_with_retry
from kc2ak.redact import redact, register_secret

# Admin credentials (KC_REALM_ADMIN/KC_ADMIN_PASSWORD or a service account)
# authenticate against the master realm via the built-in admin-cli client,
# same as `kcadm.sh config credentials`. This is independent of --realm,
# which only selects which realm's data is read afterwards.
_AUTH_REALM = "master"
_ADMIN_CLIENT_ID = "admin-cli"


class KeycloakAuthError(Exception):
    """Raised when Keycloak rejects the configured credentials."""


class KeycloakClient:
    def __init__(
        self,
        base_url: str,
        *,
        realm_admin: str | None = None,
        admin_password: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._client = build_client(base_url.rstrip("/"), transport=transport)
        self._realm_admin = realm_admin
        self._admin_password = admin_password
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token: str | None = None
        # Registered here too (not just in config.py) so a credential that
        # echoes back in an error response is redacted even if the caller
        # constructed this client without going through Config.
        register_secret(admin_password, client_secret)

    def close(self) -> None:
        self._client.close()

    def authenticate(self) -> None:
        """Acquire an access token, raising KeycloakAuthError on rejection."""
        if self._realm_admin and self._admin_password:
            form = {
                "grant_type": "password",
                "client_id": _ADMIN_CLIENT_ID,
                "username": self._realm_admin,
                "password": self._admin_password,
            }
        else:
            if not (self._client_id and self._client_secret):
                raise KeycloakAuthError(
                    "no credentials configured: need realm_admin+admin_password or "
                    "client_id+client_secret"
                )
            form = {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            }
        response = request_with_retry(
            self._client,
            "POST",
            f"/realms/{_AUTH_REALM}/protocol/openid-connect/token",
            data=form,
        )
        if response.status_code != 200:
            raise KeycloakAuthError(
                redact(f"Keycloak rejected credentials: {response.status_code} {response.text}")
            )
        token = str(response.json()["access_token"])
        register_secret(token)
        self._access_token = token

    def _auth_headers(self) -> dict[str, str]:
        if not self._access_token:
            raise KeycloakAuthError("not authenticated: call authenticate() first")
        return {"Authorization": f"Bearer {self._access_token}"}

    def get_users(self, realm: str, *, page_size: int = 100) -> Iterator[dict[str, Any]]:
        """Paginate GET /admin/realms/{realm}/users via first/max."""
        first = 0
        while True:
            response = request_with_retry(
                self._client,
                "GET",
                f"/admin/realms/{realm}/users",
                params={"first": first, "max": page_size},
                headers=self._auth_headers(),
            )
            response.raise_for_status()
            page = response.json()
            if not page:
                return
            yield from page
            if len(page) < page_size:
                return
            first += page_size
