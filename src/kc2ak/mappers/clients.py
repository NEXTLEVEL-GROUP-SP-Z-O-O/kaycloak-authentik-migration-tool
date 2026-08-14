"""Keycloak OIDC client -> Authentik OAuth2Provider + Application mapping.
Pure: no I/O. See .chief/milestone-1/_contract/03-entity-mapping.md.

Protocol mapper translation (the whitelist -> ScopeMapping) lives in
mappers/protocol_mappers.py, not this module. `unmapped_client_fields`
below covers only the contract's "Not carried over" list; migrate_clients
in migrator.py merges it with protocol_mappers.translate_client_protocol_mappers'
own unmapped entries into the same per-entity `unmapped` list.
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

# Authentik's own default scopes -- a Keycloak defaultClientScopes entry
# matching one of these is not lost data: standard_scope_mappings() below
# attaches the equivalent to every created provider, gated on the source
# client declaring it (.chief/milestone-1/_contract/03-entity-mapping.md's
# "Standard scopes on a created provider"). Before task-5c, a provider
# created through authentik's API got no property mappings at all -- unlike
# one created through the UI -- so this comment was previously aspirational,
# not true.
_AUTHENTIK_DEFAULT_SCOPES = frozenset({"email", "openid", "profile"})

# authentik's GrantTypesEnum, read from /api/v3/schema/ on a live 2026.5.6
# instance. The field does not exist below authentik 2026.5; older versions
# ignore it, which is why it is always sent rather than version-gated -- an
# ignored key costs nothing, a missing one silently loses the mapping.
# Note the enum has no CIBA member: Keycloak's CIBA grant has no equivalent
# here and is reported instead (see unmapped_client_fields).
_GRANT_AUTHORIZATION_CODE = "authorization_code"
_GRANT_IMPLICIT = "implicit"
_GRANT_HYBRID = "hybrid"
_GRANT_REFRESH_TOKEN = "refresh_token"
_GRANT_CLIENT_CREDENTIALS = "client_credentials"
_GRANT_PASSWORD = "password"
_GRANT_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"

# Keycloak client attributes that toggle grants the client representation has
# no boolean field for. Absent means Keycloak's own default, which differs per
# attribute -- see map_grant_types.
_KC_ATTR_DEVICE_CODE = "oauth2.device.authorization.grant.enabled"
_KC_ATTR_CIBA = "oidc.ciba.grant.enabled"
_KC_ATTR_USE_REFRESH_TOKENS = "use.refresh.tokens"
_KC_ATTR_CC_REFRESH_TOKEN = "client_credentials.use_refresh_token"
# Confirmed live against Keycloak 25.0.6 by writing them through the admin API
# and reading the client back -- not taken from memory or docs.
_KC_ATTR_BACKCHANNEL_LOGOUT_URL = "backchannel.logout.url"
_KC_ATTR_FRONTCHANNEL_LOGOUT_URL = "frontchannel.logout.url"
_KC_ATTR_POST_LOGOUT_REDIRECT_URIS = "post.logout.redirect.uris"

# Keycloak joins multi-valued client attributes with "##". For post-logout
# redirect URIs it also defines two sentinels: "+" reuses the client's own
# redirect URIs, "-" allows none.
_KC_MULTIVALUE_SEPARATOR = "##"
_KC_POST_LOGOUT_SAME_AS_REDIRECTS = "+"
_KC_POST_LOGOUT_NONE = "-"

# Every one uses scope_name="openid" rather than the scope's own name:
# task-5c confirmed live that a Keycloak *default* client scope's claims are
# present unconditionally, regardless of what the token request asks for,
# while an authentik ScopeMapping only fires when its own scope_name is in
# the request. "openid" is the only scope_name guaranteed present on every
# OIDC request, so it is the one choice that reproduces Keycloak's actual
# behaviour instead of silently dropping these claims whenever a client
# happens to request a narrower scope than usual.
#
# Content is deliberately narrower than authentik's own shipped managed
# mappings (task-5d, correcting task-5c): only a claim reproducible
# *faithfully* from migrated data is emitted, same rule the protocol mapper
# whitelist follows. "openid" carries no claims by the OIDC spec itself.
# "profile" omits authentik's own `given_name`/`family_name`/`nickname` --
# Keycloak's firstName/lastName collapse into authentik's single `name`
# field, so the parts are not separable, and authentik's own `nickname` is
# just a second copy of username under another key, not migrated data of
# its own. It also omits `groups`: confirmed live in task-5c that authentik
# concatenates same-key list values across mappings rather than
# overwriting, so a client with its own translated
# oidc-group-membership-mapper would receive every group listed twice;
# group membership belongs to that mapper alone, and dropping it here loses
# nothing (it was never data unique to the profile scope). "email" omits
# `email_verified` -- authentik does not track email verification, so a
# copy would hardcode `true` for every migrated user regardless of their
# real Keycloak `emailVerified` state, and relying parties treat that claim
# as a security assertion.
_STANDARD_SCOPE_EXPRESSIONS = {
    "openid": "return {}",
    "profile": "return {'name': user.name, 'preferred_username': user.username}",
    "email": "return {'email': user.email}",
}

# Standard claims dropped from the copies above because they cannot be
# reproduced faithfully -- recorded in `unmapped` when their scope is
# actually attached, per .chief/milestone-1/_contract/03-entity-mapping.md's
# "What the copies may contain". `groups` is deliberately not here: it is
# not lost data (Keycloak's own `profile` scope never included it), just an
# authentik-default addition dropped to avoid the duplication bug above, so
# nothing needs recording.
_DROPPED_STANDARD_CLAIMS = {
    "profile": (
        ("given_name", "Keycloak firstName/lastName collapse into authentik's single name field"),
        ("family_name", "Keycloak firstName/lastName collapse into authentik's single name field"),
    ),
    "email": (
        (
            "email_verified",
            "authentik does not track email verification; hardcoding true would "
            "misrepresent an unverified address as verified",
        ),
    ),
}

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
        "redirect_uris": [map_redirect_uri(uri) for uri in kc_client.get("redirectUris") or []]
        + map_post_logout_redirect_uris(kc_client),
        "authorization_flow": authorization_flow,
        "invalidation_flow": invalidation_flow,
        "grant_types": map_grant_types(kc_client),
    }
    payload.update(map_logout(kc_client))
    if secret is not None:
        payload["client_secret"] = secret
    return payload


def map_grant_types(kc_client: dict[str, Any]) -> list[str]:
    """Translate Keycloak's per-client flow toggles into authentik's
    `grant_types` list, in enum order.

    authentik defaults an omitted `grant_types` to *permissive* -- 2026.5
    backfilled every pre-existing provider with all seven to preserve
    behaviour. So writing this list can only ever narrow what a provider
    allows, which is the point: it narrows it to what the source client
    actually declared. That also makes `refresh_token` load-bearing. Dropping
    it would leave a migrated app unable to renew a token, so it is included
    whenever Keycloak itself would issue one.

    Keycloak's refresh-token switches live in attributes with opposite
    defaults: `use.refresh.tokens` is on unless explicitly "false", while
    `client_credentials.use_refresh_token` is off unless explicitly "true"
    (Keycloak stopped issuing refresh tokens for client_credentials in 12.0).
    Both are read as "absent means Keycloak's default", never as "absent means
    off" -- so a misremembered attribute name degrades to Keycloak's own
    default rather than silently stripping a grant.
    """
    attributes = kc_client.get("attributes") or {}
    standard = bool(kc_client.get("standardFlowEnabled"))
    implicit = bool(kc_client.get("implicitFlowEnabled"))
    direct_access = bool(kc_client.get("directAccessGrantsEnabled"))
    service_accounts = bool(kc_client.get("serviceAccountsEnabled"))

    grants: list[str] = []
    if standard:
        grants.append(_GRANT_AUTHORIZATION_CODE)
    if implicit:
        grants.append(_GRANT_IMPLICIT)
    # Keycloak has no hybrid toggle of its own: the hybrid flow is reachable
    # exactly when a client permits both an authorization code and an
    # implicit response type, so it is derived rather than widened.
    if standard and implicit:
        grants.append(_GRANT_HYBRID)
    if service_accounts:
        grants.append(_GRANT_CLIENT_CREDENTIALS)
    if direct_access:
        grants.append(_GRANT_PASSWORD)
    if attributes.get(_KC_ATTR_DEVICE_CODE) == "true":
        grants.append(_GRANT_DEVICE_CODE)

    # Ordered after the grants that earn it so the list reads in enum order
    # once inserted; see the refresh-token reasoning above.
    user_flow_refresh = (standard or direct_access) and attributes.get(
        _KC_ATTR_USE_REFRESH_TOKENS
    ) != "false"
    cc_refresh = service_accounts and attributes.get(_KC_ATTR_CC_REFRESH_TOKEN) == "true"
    if user_flow_refresh or cc_refresh:
        grants.insert(
            grants.index(_GRANT_CLIENT_CREDENTIALS)
            if _GRANT_CLIENT_CREDENTIALS in grants
            else len(grants),
            _GRANT_REFRESH_TOKEN,
        )

    return grants


def map_logout(kc_client: dict[str, Any]) -> dict[str, str]:
    """Keycloak's logout channel and URL as authentik's `logout_method` /
    `logout_uri` (both added in authentik 2026.5).

    Keycloak can hold a back-channel and a front-channel logout URL at the
    same time; authentik holds one method and one URL. The client's own
    `frontchannelLogout` boolean is the discriminator -- it is exactly the
    switch Keycloak itself uses to decide which channel a logout goes
    through -- so this picks the URL for the selected channel rather than
    guessing between two populated fields. The unselected channel's URL, if
    Keycloak also has one, is reported by `unmapped_client_fields`.

    Returns an empty dict when the selected channel has no URL: authentik's
    `logout_method` alone carries no information without somewhere to send
    the logout, and writing a method with no URI would be a bare default.
    """
    attributes = kc_client.get("attributes") or {}
    frontchannel = bool(kc_client.get("frontchannelLogout"))
    attr = _KC_ATTR_FRONTCHANNEL_LOGOUT_URL if frontchannel else _KC_ATTR_BACKCHANNEL_LOGOUT_URL
    url = attributes.get(attr)
    if not url:
        return {}
    return {
        "logout_method": "frontchannel" if frontchannel else "backchannel",
        "logout_uri": url,
    }


def map_post_logout_redirect_uris(kc_client: dict[str, Any]) -> list[dict[str, str]]:
    """Keycloak's `post.logout.redirect.uris` as authentik redirect-URI
    entries carrying `redirect_uri_type: "logout"` (the second member of
    RedirectURITypeEnum, added in 2026.5).

    Keycloak's two sentinels are honoured rather than treated as URLs: "+"
    means "the same URIs this client already redirects to", so it expands to
    exactly those, and "-" means none. Anything else is a "##"-separated
    list, translated through the same wildcard rules as an authorization
    redirect URI.
    """
    attributes = kc_client.get("attributes") or {}
    raw = (attributes.get(_KC_ATTR_POST_LOGOUT_REDIRECT_URIS) or "").strip()
    if not raw or raw == _KC_POST_LOGOUT_NONE:
        return []
    if raw == _KC_POST_LOGOUT_SAME_AS_REDIRECTS:
        sources = list(kc_client.get("redirectUris") or [])
    else:
        sources = [part for part in raw.split(_KC_MULTIVALUE_SEPARATOR) if part]
    return [{**map_redirect_uri(uri), "redirect_uri_type": "logout"} for uri in sources]


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


def standard_scope_mappings(
    kc_client: dict[str, Any], client_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Returns (ScopeMapping create payloads, unmapped entries) for
    authentik's standard openid/profile/email claims, gated on the source
    client (.chief/milestone-1/_contract/03-entity-mapping.md's "Standard
    scopes on a created provider"). `openid` is always included;
    `profile`/`email` only when the Keycloak client declares them in
    `defaultClientScopes` or `optionalClientScopes` -- attaching them
    unconditionally would widen a token for a client whose admin
    deliberately removed one, which is as silent a change as dropping
    claims and the harder one to notice. A scope in neither list is
    faithfully reproduced by attaching nothing, so it is never reported in
    `unmapped` -- unlike the claims _DROPPED_STANDARD_CLAIMS names, which
    are only omitted because this tool cannot reproduce them faithfully and
    so are reported, same as an unwhitelisted protocol mapper. Every
    surviving scope's expression is non-empty by construction (`openid`'s
    is deliberately `{}`), so there is currently no case where a scope
    would need skipping entirely -- if a future edit ever drops every claim
    from `profile` or `email`, that scope must stop being attached rather
    than creating an empty mapping.
    """
    declared = set(kc_client.get("defaultClientScopes") or []) | set(
        kc_client.get("optionalClientScopes") or []
    )
    scopes = ["openid", *(s for s in ("profile", "email") if s in declared)]
    payloads = [
        {
            "name": f"kc2ak: {client_id} / standard-{scope}",
            "scope_name": "openid",
            "description": "",
            "expression": _STANDARD_SCOPE_EXPRESSIONS[scope],
        }
        for scope in scopes
    ]
    unmapped = [
        {"type": "standard_scope_claim", "name": claim_name, "why": why}
        for scope in scopes
        for claim_name, why in _DROPPED_STANDARD_CLAIMS.get(scope, ())
    ]
    return payloads, unmapped


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
    attributes = kc_client.get("attributes") or {}
    # The four flow flags and the device-code attribute used to be listed here
    # as "not carried over"; map_grant_types now carries all five into
    # authentik's `grant_types`, so reporting them would be false. CIBA is the
    # one that stays: authentik's GrantTypesEnum has no member for it, so the
    # grant is genuinely lost and an operator has to know.
    if attributes.get(_KC_ATTR_CIBA) == "true":
        add(_KC_ATTR_CIBA)
    # authentik holds one logout channel; Keycloak can hold both. map_logout
    # carries the one frontchannelLogout selects, so the other is genuinely
    # lost whenever Keycloak has a URL for it too.
    unselected = (
        _KC_ATTR_BACKCHANNEL_LOGOUT_URL
        if kc_client.get("frontchannelLogout")
        else _KC_ATTR_FRONTCHANNEL_LOGOUT_URL
    )
    if attributes.get(unselected) and map_logout(kc_client):
        add(unselected)
    if any(key in attributes for key in _TOKEN_LIFESPAN_ATTRS):
        add("token_lifespans")
    extra_scopes = set(kc_client.get("defaultClientScopes") or []) - _AUTHENTIK_DEFAULT_SCOPES
    if extra_scopes:
        add("defaultClientScopes")

    return entries
