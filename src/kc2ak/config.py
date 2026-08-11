"""Environment-only configuration. Credentials never come from CLI flags —
see .chief/milestone-1/_contract/01-cli-interface.md's environment table.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from kc2ak.errors import UsageError
from kc2ak.redact import register_secret


@dataclass(frozen=True)
class Config:
    kc_url: str
    kc_realm_admin: str | None
    kc_admin_password: str | None
    kc_client_id: str | None
    kc_client_secret: str | None
    ak_url: str
    ak_token: str

    @classmethod
    def from_env(cls) -> Config:
        kc_url = _require_env("KC_URL")
        ak_url = _require_env("AK_URL")
        ak_token = _require_env("AK_TOKEN")

        kc_realm_admin = os.environ.get("KC_REALM_ADMIN") or None
        kc_admin_password = os.environ.get("KC_ADMIN_PASSWORD") or None
        kc_client_id = os.environ.get("KC_CLIENT_ID") or None
        kc_client_secret = os.environ.get("KC_CLIENT_SECRET") or None

        has_password_creds = bool(kc_realm_admin and kc_admin_password)
        has_client_creds = bool(kc_client_id and kc_client_secret)
        if not has_password_creds and not has_client_creds:
            raise UsageError(
                "Keycloak credentials missing: set KC_REALM_ADMIN + KC_ADMIN_PASSWORD, "
                "or KC_CLIENT_ID + KC_CLIENT_SECRET"
            )

        # Register secrets before returning, so anything that fails between
        # here and a client being constructed still redacts correctly.
        register_secret(kc_admin_password, kc_client_secret, ak_token)

        return cls(
            kc_url=kc_url,
            kc_realm_admin=kc_realm_admin,
            kc_admin_password=kc_admin_password,
            kc_client_id=kc_client_id,
            kc_client_secret=kc_client_secret,
            ak_url=ak_url,
            ak_token=ak_token,
        )


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise UsageError(f"{name} is not set")
    return value
