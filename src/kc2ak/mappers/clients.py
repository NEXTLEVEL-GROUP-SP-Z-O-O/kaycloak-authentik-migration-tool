"""Keycloak OIDC client -> Authentik OAuth2Provider + Application mapping.
Pure: no I/O. See .chief/milestone-1/_contract/03-entity-mapping.md.

Protocol mapper translation (the whitelist -> ScopeMapping) is task-5b, not
this module -- deliberately left untouched. `unmapped_client_fields` covers
only the contract's "Not carried over" list; 5b appends protocol-mapper
entries to the same `unmapped` list the migrator builds per entity.
"""

from __future__ import annotations

import re
from typing import Any

# Keycloak auto-creates these in every realm; they're realm infrastructure,
# not migratable application data, and migrating them would pollute
# Authentik with providers like "admin-cli". Confirmed against a live
# Keycloak 25 GET /clients response.
BUILTIN_CLIENT_IDS = frozenset(
    {
        "account",
        "account-console",
        "admin-cli",
        "broker",
        "realm-management",
        "security-admin-console",
    }
)

# Authentik's own default scopes granted to every OAuth2Provider -- a
# Keycloak defaultClientScopes entry matching one of these is not lost data,
# it is the equivalent already present on the authentik side.
_AUTHENTIK_DEFAULT_SCOPES = frozenset({"email", "openid", "profile"})

# Per-client token lifespan overrides live in Keycloak's free-form
# `attributes` map, not as top-level fields.
_TOKEN_LIFESPAN_ATTRS = (
    "access.token.lifespan",
    "client.session.idle.timeout",
    "client.session.max.lifespan",
    "client.offline.session.idle.timeout",
    "client.offline.session.max.lifespan",
)


def is_migratable_client(kc_client: dict[str, Any]) -> bool:
    """True for realm-defined OIDC clients this tool migrates. False for
    Keycloak's built-in clients and non-OIDC (e.g. SAML) clients -- neither
    is realm data to carry over.
    """
    protocol = kc_client.get("protocol", "openid-connect")
    return protocol == "openid-connect" and kc_client["clientId"] not in BUILTIN_CLIENT_IDS


def slugify(client_id: str) -> str:
    """Lowercased, non-alphanumerics replaced with '-', per the contract."""
    return re.sub(r"[^a-z0-9]+", "-", client_id.lower()).strip("-")


def map_redirect_uri(uri: str) -> dict[str, str]:
    """`strict` for a plain URI, `regex` (wildcard translated) for one
    containing `*`. The pattern is anchored so a wildcard cannot match a
    wider string than intended -- e.g. `https://evilexample.com/x` must not
    match `https://*.example.com/*`, which an unanchored substring match
    would allow.
    """
    if "*" not in uri:
        return {"matching_mode": "strict", "url": uri}
    pattern = "^" + ".*".join(re.escape(part) for part in uri.split("*")) + "$"
    return {"matching_mode": "regex", "url": pattern}


def map_provider(
    kc_client: dict[str, Any],
    secret: str | None,
    *,
    authorization_flow: str,
    invalidation_flow: str,
) -> dict[str, Any]:
    """Map a Keycloak OIDC client to an Authentik OAuth2Provider create/update
    payload. `secret` is None for a public client -- carried over verbatim
    for a confidential one, so the client application keeps working with
    only an issuer URL change.
    """
    client_id = kc_client["clientId"]
    payload: dict[str, Any] = {
        "name": kc_client.get("name") or client_id,
        "client_id": client_id,
        "client_type": "public" if kc_client.get("publicClient", False) else "confidential",
        "redirect_uris": [map_redirect_uri(uri) for uri in kc_client.get("redirectUris") or []],
        "authorization_flow": authorization_flow,
        "invalidation_flow": invalidation_flow,
    }
    if secret is not None:
        payload["client_secret"] = secret
    return payload


def map_application(client_id: str, provider_pk: int, name: str | None = None) -> dict[str, Any]:
    """Map to an Authentik Application create payload. `slug` derives from
    `clientId`, not `name` -- it is the stable natural key even if a client
    is renamed in Keycloak.
    """
    return {
        "name": name or client_id,
        "slug": slugify(client_id),
        "provider": provider_pk,
    }


def unmapped_client_fields(kc_client: dict[str, Any]) -> list[dict[str, str]]:
    """The contract's "Not carried over" list, recorded only where something
    real would be lost -- an unset/false field carries no information, so
    it is not reported (an unconditional entry on every client would teach
    operators to ignore `unmapped`).

    Client roles are deliberately not checked here: the contract's
    authoritative "Endpoints read" table has no endpoint for them, and role
    migration is out of scope for the whole milestone
    (.chief/milestone-1/_goal/01-migration-scope.md) -- there is nothing to
    inspect without guessing at an endpoint the contract never sanctioned.
    """
    entries: list[dict[str, str]] = []

    def add(name: str) -> None:
        entries.append({"type": "client_field", "name": name, "why": "not carried over"})

    if kc_client.get("webOrigins"):
        add("webOrigins")
    for flag in ("standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled"):
        if kc_client.get(flag):
            add(flag)
    if kc_client.get("serviceAccountsEnabled"):
        add("serviceAccountsEnabled")
    attributes = kc_client.get("attributes") or {}
    if any(key in attributes for key in _TOKEN_LIFESPAN_ATTRS):
        add("token_lifespans")
    extra_scopes = set(kc_client.get("defaultClientScopes") or []) - _AUTHENTIK_DEFAULT_SCOPES
    if extra_scopes:
        add("defaultClientScopes")

    return entries
