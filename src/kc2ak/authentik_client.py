"""Thin Authentik API wrapper: auth, retry only. No business logic, no
mapping — see .chief/project.md's Client -> Mapper -> Migrator layering.
"""

from __future__ import annotations

from typing import Any

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

    def find_user_by_username(self, username: str) -> dict[str, Any] | None:
        """Exact-match lookup on the natural key's unique half. Confirmed
        against a live instance: `?username=` is an exact filter.
        """
        response = request_with_retry(
            self._client, "GET", "/api/v3/core/users/", params={"username": username}
        )
        response.raise_for_status()
        results: list[dict[str, Any]] = response.json().get("results", [])
        return results[0] if results else None

    def find_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Exact-match lookup used only to flag (not block) a duplicate
        email under a different username -- email is not unique in
        Authentik. Empty email never counts as a duplicate.
        """
        if not email:
            return None
        response = request_with_retry(
            self._client, "GET", "/api/v3/core/users/", params={"email": email}
        )
        response.raise_for_status()
        results: list[dict[str, Any]] = response.json().get("results", [])
        return results[0] if results else None

    def create_user(self, payload: dict[str, Any]) -> httpx.Response:
        """POST /api/v3/core/users/. Raw response -- the caller decides
        CREATED vs FAILED from the status code, per the report contract.
        """
        return request_with_retry(self._client, "POST", "/api/v3/core/users/", json=payload)

    def update_user(self, pk: int, payload: dict[str, Any]) -> httpx.Response:
        """PATCH /api/v3/core/users/{pk}/, only reached under --update-existing.
        Raw response, same convention as create_user.
        """
        return request_with_retry(self._client, "PATCH", f"/api/v3/core/users/{pk}/", json=payload)

    def find_group_by_name(self, name: str) -> dict[str, Any] | None:
        """Exact-match lookup on the group natural key (`name`). The result
        includes a `users` field (member pks), confirmed against a live
        instance, which callers use to detect already-present members
        without a second request.
        """
        response = request_with_retry(
            self._client, "GET", "/api/v3/core/groups/", params={"name": name}
        )
        response.raise_for_status()
        results: list[dict[str, Any]] = response.json().get("results", [])
        return results[0] if results else None

    def create_group(self, payload: dict[str, Any]) -> httpx.Response:
        """POST /api/v3/core/groups/. Raw response, same convention as
        create_user.
        """
        return request_with_retry(self._client, "POST", "/api/v3/core/groups/", json=payload)

    def update_group(self, pk: str, payload: dict[str, Any]) -> httpx.Response:
        """PATCH /api/v3/core/groups/{pk}/, only reached under --update-existing.
        Raw response, same convention as create_group.
        """
        return request_with_retry(self._client, "PATCH", f"/api/v3/core/groups/{pk}/", json=payload)

    def recovery_flow_configured(self) -> bool:
        """True if the default brand has a recovery flow assigned.
        _goal/02-safety-and-blast-radius.md precondition: --send-recovery-email
        must abort up front if the brand has no recovery flow at all.
        """
        response = request_with_retry(self._client, "GET", "/api/v3/core/brands/")
        response.raise_for_status()
        results: list[dict[str, Any]] = response.json().get("results", [])
        brand = next((b for b in results if b.get("default")), results[0] if results else None)
        return bool(brand and brand.get("flow_recovery"))

    def get_email_stage(self, stage_uuid: str) -> dict[str, Any] | None:
        """GET /api/v3/stages/email/{uuid}/. None on 404 (unknown/malformed
        UUID -- confirmed live, both come back 404, not a validation error).

        Used for two of the three --send-recovery-email preconditions: the
        stage's mere existence covers "the --email-stage UUID is present and
        valid"; `use_global_settings` or a configured `host` is the closest
        proxy authentik's API exposes for "SMTP is configured" -- there is no
        endpoint that reports whether the configured SMTP actually works
        (confirmed live: a 204 from recovery_email only means the send was
        queued to the worker, not that delivery succeeded).
        """
        response = request_with_retry(self._client, "GET", f"/api/v3/stages/email/{stage_uuid}/")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        return result

    def send_recovery_email(self, user_pk: int, email_stage: str) -> httpx.Response:
        """POST /api/v3/core/users/{id}/recovery_email/. `email_stage` is a
        **query** parameter, not a JSON body field, despite
        _contract/03-entity-mapping.md's example -- confirmed live against
        authentik 2024.10.5: the body form 400s with "Email stage does not
        exist" even for a real stage, the query form 204s. Raw response, same
        convention as create_user/create_group.
        """
        return request_with_retry(
            self._client,
            "POST",
            f"/api/v3/core/users/{user_pk}/recovery_email/",
            params={"email_stage": email_stage},
        )

    def add_user_to_group(self, group_pk: str, user_pk: int) -> httpx.Response:
        """POST /api/v3/core/groups/{pk}/add_user/ with the integer user pk
        (not the uuid). Confirmed idempotent against a live instance -- a
        repeat add_user for an existing member still returns 204.
        """
        return request_with_retry(
            self._client,
            "POST",
            f"/api/v3/core/groups/{group_pk}/add_user/",
            json={"pk": user_pk},
        )
