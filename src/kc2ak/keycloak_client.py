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
        yield from self._paginate(f"/admin/realms/{realm}/users", page_size=page_size)

    def get_groups(self, realm: str, *, page_size: int = 100) -> Iterator[dict[str, Any]]:
        """Paginate GET /admin/realms/{realm}/groups via first/max.

        Nested subgroups are not returned by this endpoint (confirmed
        against a live Keycloak 25 instance) -- only their parent's
        `subGroupCount` hints at their existence. See
        mappers/groups.py:is_nested.
        """
        yield from self._paginate(f"/admin/realms/{realm}/groups", page_size=page_size)

    def get_group_members(
        self, realm: str, group_id: str, *, page_size: int = 100
    ) -> Iterator[dict[str, Any]]:
        """Paginate GET /admin/realms/{realm}/groups/{id}/members via first/max."""
        yield from self._paginate(
            f"/admin/realms/{realm}/groups/{group_id}/members", page_size=page_size
        )

    def get_clients(self, realm: str, *, page_size: int = 100) -> Iterator[dict[str, Any]]:
        """Paginate GET /admin/realms/{realm}/clients via first/max. Includes
        Keycloak's built-in clients and non-OIDC clients -- callers filter
        with mappers.clients.is_migratable_client.
        """
        yield from self._paginate(f"/admin/realms/{realm}/clients", page_size=page_size)

    def get_roles(self, realm: str, *, page_size: int = 100) -> Iterator[dict[str, Any]]:
        """Paginate GET /admin/realms/{realm}/roles via first/max. Includes
        Keycloak's built-in roles -- callers filter with
        mappers.roles.builtin_role_names. Each item's `composite` flag is
        enough to detect (not expand) a composite role; see
        mappers/roles.py:is_composite.
        """
        yield from self._paginate(f"/admin/realms/{realm}/roles", page_size=page_size)

    def get_user_realm_roles(self, realm: str, user_id: str) -> list[dict[str, Any]]:
        """GET /admin/realms/{realm}/users/{id}/role-mappings/realm -- the
        user's **direct** role assignments only, not composite-expanded.
        Confirmed against Keycloak 25.0.6 in milestone-2 task-1: a user
        assigned only a composite role returns just that role's own name
        here, not its constituents (see
        .chief/milestone-2/_contract/01-role-mapping.md's amendment). Not
        paginated -- Keycloak returns the full list in one response.
        """
        response = request_with_retry(
            self._client,
            "GET",
            f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
            headers=self._auth_headers(),
        )
        response.raise_for_status()
        result: list[dict[str, Any]] = response.json()
        return result

    def get_client_roles(
        self, realm: str, client_id: str, *, page_size: int = 100
    ) -> Iterator[dict[str, Any]]:
        """Paginate GET /admin/realms/{realm}/clients/{id}/roles via
        first/max. `client_id` here is Keycloak's internal `id` (uuid),
        matching get_client_secret. Read once per in-scope client purely to
        report -- client roles are never migrated
        (.chief/milestone-2/_goal/01-roles-scope.md).
        """
        yield from self._paginate(
            f"/admin/realms/{realm}/clients/{client_id}/roles", page_size=page_size
        )

    def get_identity_providers(
        self, realm: str, *, page_size: int = 100
    ) -> Iterator[dict[str, Any]]:
        """Paginate GET /admin/realms/{realm}/identity-provider/instances via
        first/max. `config.clientSecret` on every result is the literal
        string "**********" -- confirmed live, no route returns it unmasked
        (.chief/milestone-2/_contract/02-idp-mapping.md). `internalId` is
        each provider's own uuid, distinct from its `alias`.
        """
        yield from self._paginate(
            f"/admin/realms/{realm}/identity-provider/instances", page_size=page_size
        )

    def get_idp_mappers(self, realm: str, alias: str) -> list[dict[str, Any]]:
        """GET /admin/realms/{realm}/identity-provider/instances/{alias}/mappers.
        Not paginated -- Keycloak returns the full list in one response, same
        as get_user_realm_roles. Read once per in-scope IdP purely to report
        -- IdP mappers are never translated
        (.chief/milestone-2/_contract/02-idp-mapping.md).
        """
        response = request_with_retry(
            self._client,
            "GET",
            f"/admin/realms/{realm}/identity-provider/instances/{alias}/mappers",
            headers=self._auth_headers(),
        )
        response.raise_for_status()
        result: list[dict[str, Any]] = response.json()
        return result

    def get_federated_identities(self, realm: str, user_id: str) -> list[dict[str, Any]]:
        """GET /admin/realms/{realm}/users/{id}/federated-identity. Not
        paginated -- Keycloak returns the full list in one response, same as
        get_user_realm_roles. `identityProvider` matches an identity
        provider's `alias`; `userId` is the external identifier Keycloak
        recorded for that link (.chief/milestone-2/_contract/02-idp-mapping.md).
        """
        response = request_with_retry(
            self._client,
            "GET",
            f"/admin/realms/{realm}/users/{user_id}/federated-identity",
            headers=self._auth_headers(),
        )
        response.raise_for_status()
        result: list[dict[str, Any]] = response.json()
        return result

    def get_client_secret(self, realm: str, client_id: str) -> str:
        """GET /admin/realms/{realm}/clients/{id}/client-secret. `client_id`
        here is Keycloak's internal `id` (uuid), not the OIDC `clientId`.
        Registers the secret for redaction before returning it, so it never
        reaches a log line unredacted even from this same call's own debug
        logging.
        """
        response = request_with_retry(
            self._client,
            "GET",
            f"/admin/realms/{realm}/clients/{client_id}/client-secret",
            headers=self._auth_headers(),
        )
        response.raise_for_status()
        secret = str(response.json()["value"])
        register_secret(secret)
        return secret

    def _paginate(self, path: str, *, page_size: int) -> Iterator[dict[str, Any]]:
        first = 0
        while True:
            response = request_with_retry(
                self._client,
                "GET",
                path,
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
