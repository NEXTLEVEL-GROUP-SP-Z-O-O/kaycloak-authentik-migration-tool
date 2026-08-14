"""Fixture-backed tests for the client mapper. tests/fixtures/kc_clients.json
is a real GET /admin/realms/{realm}/clients response captured from a live
Keycloak 25 instance seeded from deploy/keycloak/realm-kc2ak-test.json --
includes Keycloak's auto-created built-in clients alongside confidential-app.
"""

import json
from pathlib import Path
from typing import Any

from kc2ak.mappers.clients import (
    is_migratable_client,
    map_application,
    map_grant_types,
    map_provider,
    map_redirect_uri,
    slugify,
    standard_scope_mappings,
    unmapped_client_fields,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _clients() -> dict[str, dict[str, Any]]:
    data = json.loads((FIXTURES / "kc_clients.json").read_text())
    return {c["clientId"]: c for c in data}


# --- is_migratable_client ---------------------------------------------------


def test_confidential_app_is_migratable() -> None:
    assert is_migratable_client(_clients()["confidential-app"]) is True


def test_builtin_clients_are_not_migratable() -> None:
    clients = _clients()
    for builtin in (
        "account",
        "account-console",
        "admin-cli",
        "broker",
        "realm-management",
        "security-admin-console",
    ):
        assert is_migratable_client(clients[builtin]) is False, builtin


def test_non_oidc_protocol_is_not_migratable() -> None:
    saml_client = {"clientId": "saml-app", "protocol": "saml"}
    assert is_migratable_client(saml_client) is False


# --- slug derivation ---------------------------------------------------


def test_slugify_lowercases_and_replaces_non_alphanumerics() -> None:
    assert slugify("Confidential App") == "confidential-app"
    assert slugify("My_Client.123") == "my-client-123"
    assert slugify("confidential-app") == "confidential-app"


# --- redirect URI matching mode ---------------------------------------------------


def test_plain_redirect_uri_is_strict() -> None:
    assert map_redirect_uri("https://app.example.com/callback") == {
        "matching_mode": "strict",
        "url": "https://app.example.com/callback",
    }


def test_wildcard_redirect_uri_is_regex() -> None:
    mapped = map_redirect_uri("https://*.example.com/*")
    assert mapped["matching_mode"] == "regex"
    assert mapped["url"] == r"^https://.*\.example\.com/.*$"


def test_wildcard_regex_matches_intended_hosts_and_paths() -> None:
    import re

    pattern = map_redirect_uri("https://*.example.com/*")["url"]
    assert re.fullmatch(pattern, "https://app.example.com/callback")
    assert re.fullmatch(pattern, "https://sso.example.com/anything/here")


def test_wildcard_regex_does_not_widen_beyond_the_intended_domain() -> None:
    import re

    pattern = map_redirect_uri("https://*.example.com/*")["url"]
    # A lookalike host must not match -- the escaped literal dot is what
    # blocks "evilexample.com" from satisfying ".example.com".
    assert re.fullmatch(pattern, "https://evilexample.com/x") is None
    assert re.fullmatch(pattern, "https://app.example.com.evil.com/x") is None
    # The ^ anchor is what protects against a matcher using search()
    # semantics: without it, a malicious URL that merely *contains* a valid
    # https://…example.com/ substring after some other scheme/host would
    # still match. Anchored to the start, this string legitimately fails
    # because it does not begin with "https://" at all.
    sneaky = "http://evil.com/?redirect=https://sso.example.com/callback"
    assert re.search(pattern, sneaky) is None
    assert re.fullmatch(pattern, sneaky) is None


# --- client type -----------------------------------------------------------


def test_confidential_client_maps_to_confidential_type() -> None:
    payload = map_provider(
        _clients()["confidential-app"],
        "shh",
        authorization_flow="auth-flow",
        invalidation_flow="inv-flow",
    )
    assert payload["client_type"] == "confidential"
    assert payload["client_secret"] == "shh"


def test_public_client_maps_to_public_type_with_no_secret_field() -> None:
    kc_client = {"clientId": "public-spa", "publicClient": True, "redirectUris": []}
    payload = map_provider(
        kc_client, None, authorization_flow="auth-flow", invalidation_flow="inv-flow"
    )
    assert payload["client_type"] == "public"
    assert "client_secret" not in payload


# --- provider payload --------------------------------------------------


def test_map_provider_carries_client_id_and_flows() -> None:
    payload = map_provider(
        _clients()["confidential-app"],
        "shh",
        authorization_flow="auth-flow",
        invalidation_flow="inv-flow",
    )
    assert payload["client_id"] == "confidential-app"
    assert payload["name"] == "Confidential Test App"
    assert payload["authorization_flow"] == "auth-flow"
    assert payload["invalidation_flow"] == "inv-flow"


def test_map_provider_redirect_uris_translated() -> None:
    payload = map_provider(
        _clients()["confidential-app"],
        "shh",
        authorization_flow="auth-flow",
        invalidation_flow="inv-flow",
    )
    modes = {u["url"]: u["matching_mode"] for u in payload["redirect_uris"]}
    assert modes["https://app.example.com/callback"] == "strict"
    assert modes[r"^https://.*\.example\.com/.*$"] == "regex"


def test_map_provider_falls_back_to_client_id_when_name_missing() -> None:
    kc_client = {"clientId": "no-name-client", "publicClient": True, "redirectUris": []}
    payload = map_provider(
        kc_client, None, authorization_flow="auth-flow", invalidation_flow="inv-flow"
    )
    assert payload["name"] == "no-name-client"


# --- application payload ----------------------------------------------------


def test_map_application_derives_slug_from_client_id() -> None:
    payload = map_application("Confidential App", 7)
    assert payload["slug"] == "confidential-app"
    assert payload["provider"] == 7


# --- grant types -------------------------------------------------------


def _kc(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "clientId": "app",
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
    }
    base.update(overrides)
    return base


def test_grant_types_standard_flow_carries_authorization_code_and_refresh() -> None:
    # The common case. refresh_token is not widening: Keycloak issues one for
    # the standard flow unless use.refresh.tokens is explicitly turned off.
    assert map_grant_types(_kc(standardFlowEnabled=True)) == [
        "authorization_code",
        "refresh_token",
    ]


def test_grant_types_refresh_dropped_only_when_explicitly_disabled() -> None:
    kc_client = _kc(standardFlowEnabled=True, attributes={"use.refresh.tokens": "false"})
    assert map_grant_types(kc_client) == ["authorization_code"]


def test_grant_types_absent_attribute_keeps_keycloaks_default() -> None:
    # Absent must mean Keycloak's default (on), never "off" -- a migrated app
    # that silently loses refresh_token cannot renew a token.
    assert "refresh_token" in map_grant_types(_kc(standardFlowEnabled=True, attributes={}))


def test_grant_types_hybrid_only_when_both_code_and_implicit() -> None:
    both = map_grant_types(_kc(standardFlowEnabled=True, implicitFlowEnabled=True))
    assert "hybrid" in both
    assert "hybrid" not in map_grant_types(_kc(standardFlowEnabled=True))
    assert "hybrid" not in map_grant_types(_kc(implicitFlowEnabled=True))


def test_grant_types_service_accounts_and_direct_access() -> None:
    kc_client = _kc(serviceAccountsEnabled=True, directAccessGrantsEnabled=True)
    grants = map_grant_types(kc_client)
    assert "client_credentials" in grants
    assert "password" in grants


def test_grant_types_client_credentials_refresh_is_off_unless_asked() -> None:
    # Opposite default to use.refresh.tokens: Keycloak stopped issuing these
    # for client_credentials in 12.0, so absent means off.
    assert map_grant_types(_kc(serviceAccountsEnabled=True)) == ["client_credentials"]
    opted_in = _kc(
        serviceAccountsEnabled=True,
        attributes={"client_credentials.use_refresh_token": "true"},
    )
    assert "refresh_token" in map_grant_types(opted_in)


def test_grant_types_device_code_requires_the_attribute() -> None:
    on = _kc(attributes={"oauth2.device.authorization.grant.enabled": "true"})
    assert map_grant_types(on) == ["urn:ietf:params:oauth:grant-type:device_code"]
    assert map_grant_types(_kc(attributes={})) == []


def test_grant_types_empty_when_every_flow_is_off() -> None:
    assert map_grant_types(_kc()) == []


def test_map_provider_includes_grant_types() -> None:
    payload = map_provider(
        _clients()["confidential-app"],
        secret="s",
        authorization_flow="auth-flow",
        invalidation_flow="inv-flow",
    )
    # The fixture has standard flow + direct access grants, nothing else.
    assert payload["grant_types"] == ["authorization_code", "password", "refresh_token"]


# --- unmapped fields ---------------------------------------------------


def test_unmapped_includes_web_origins_and_default_scopes_but_not_flow_flags() -> None:
    entries = unmapped_client_fields(_clients()["confidential-app"])
    names = {e["name"] for e in entries}
    assert "webOrigins" in names
    assert "defaultClientScopes" in names  # roles/basic/web-origins/acr beyond authentik's own
    assert "token_lifespans" not in names  # no lifespan attributes set in the fixture
    # The flow flags are carried into grant_types now, so reporting them as
    # "not carried over" would be a false entry.
    assert "standardFlowEnabled" not in names
    assert "directAccessGrantsEnabled" not in names
    assert all(e["type"] == "client_field" for e in entries)


def test_unmapped_reports_ciba_which_authentik_has_no_grant_for() -> None:
    kc_client = {"clientId": "ciba-app", "attributes": {"oidc.ciba.grant.enabled": "true"}}
    names = {e["name"] for e in unmapped_client_fields(kc_client)}
    assert "oidc.ciba.grant.enabled" in names


def test_unmapped_silent_when_ciba_disabled() -> None:
    kc_client = {"clientId": "plain", "attributes": {"oidc.ciba.grant.enabled": "false"}}
    assert unmapped_client_fields(kc_client) == []


def test_unmapped_empty_for_minimal_client() -> None:
    kc_client = {
        "clientId": "minimal",
        "publicClient": True,
        "redirectUris": [],
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "webOrigins": [],
        "defaultClientScopes": ["openid", "email", "profile"],
    }
    assert unmapped_client_fields(kc_client) == []


def test_unmapped_flags_token_lifespan_attributes() -> None:
    kc_client = {
        "clientId": "custom-lifespan",
        "attributes": {"access.token.lifespan": "3600"},
    }
    entries = unmapped_client_fields(kc_client)
    assert any(e["name"] == "token_lifespans" for e in entries)


# --- standard_scope_mappings (task-5c/5d) ------------------------------------


def test_standard_scope_mappings_openid_only_always_present() -> None:
    kc_client = {"clientId": "no-scopes", "defaultClientScopes": [], "optionalClientScopes": []}
    payloads, unmapped = standard_scope_mappings(kc_client, "no-scopes")
    assert [p["name"] for p in payloads] == ["kc2ak: no-scopes / standard-openid"]
    assert payloads[0]["scope_name"] == "openid"
    assert payloads[0]["expression"] == "return {}"
    assert unmapped == []


def test_standard_scope_mappings_gated_on_default_client_scopes() -> None:
    kc_client = _clients()["confidential-app"]
    payloads, unmapped = standard_scope_mappings(kc_client, "confidential-app")
    names = {p["name"] for p in payloads}
    # confidential-app's fixture declares "profile" and "email" in
    # defaultClientScopes -- both must be attached alongside openid.
    assert names == {
        "kc2ak: confidential-app / standard-openid",
        "kc2ak: confidential-app / standard-profile",
        "kc2ak: confidential-app / standard-email",
    }
    assert all(p["scope_name"] == "openid" for p in payloads)
    # task-5d: only claims reproducible faithfully from migrated data
    # survive in the copies; the rest are recorded, not approximated.
    unmapped_names = {e["name"] for e in unmapped}
    assert unmapped_names == {"given_name", "family_name", "email_verified"}
    assert all(e["type"] == "standard_scope_claim" for e in unmapped)


def test_standard_scope_mappings_gated_on_optional_client_scopes_too() -> None:
    kc_client = {
        "clientId": "opt-scope-app",
        "defaultClientScopes": [],
        "optionalClientScopes": ["email"],
    }
    payloads, unmapped = standard_scope_mappings(kc_client, "opt-scope-app")
    names = {p["name"] for p in payloads}
    assert names == {
        "kc2ak: opt-scope-app / standard-openid",
        "kc2ak: opt-scope-app / standard-email",
    }
    assert {e["name"] for e in unmapped} == {"email_verified"}


def test_standard_scope_mappings_absent_scope_is_not_attached() -> None:
    # The negative case: a scope declared in neither list is faithfully
    # reproduced by attaching nothing -- not widened, not reported as
    # unmapped (.chief/milestone-1/_contract/03-entity-mapping.md).
    kc_client = {
        "clientId": "profile-only",
        "defaultClientScopes": ["profile"],
        "optionalClientScopes": [],
    }
    payloads, unmapped = standard_scope_mappings(kc_client, "profile-only")
    names = {p["name"] for p in payloads}
    assert "kc2ak: profile-only / standard-email" not in names
    assert "kc2ak: profile-only / standard-profile" in names
    # email's dropped claim (email_verified) must not appear -- the email
    # scope was never attached at all for this client.
    assert {e["name"] for e in unmapped} == {"given_name", "family_name"}


def test_standard_scope_mappings_missing_scope_lists_still_attaches_openid() -> None:
    kc_client = {"clientId": "bare"}
    payloads, unmapped = standard_scope_mappings(kc_client, "bare")
    assert [p["name"] for p in payloads] == ["kc2ak: bare / standard-openid"]
    assert unmapped == []


# --- what the copies may contain (task-5d) -----------------------------------


def test_standard_profile_copy_omits_groups_and_given_family_name() -> None:
    kc_client = {"clientId": "app", "defaultClientScopes": ["profile"]}
    payloads, unmapped = standard_scope_mappings(kc_client, "app")
    profile = next(p for p in payloads if p["name"].endswith("standard-profile"))
    assert "groups" not in profile["expression"]
    assert "given_name" not in profile["expression"]
    assert "family_name" not in profile["expression"]
    assert (
        profile["expression"] == "return {'name': user.name, 'preferred_username': user.username}"
    )
    # groups is silently dropped (not lost data -- see clients.py), unlike
    # given_name/family_name which are reported.
    unmapped_names = {e["name"] for e in unmapped}
    assert "groups" not in unmapped_names
    assert {"given_name", "family_name"} <= unmapped_names


def test_standard_email_copy_omits_email_verified() -> None:
    kc_client = {"clientId": "app", "defaultClientScopes": ["email"]}
    payloads, unmapped = standard_scope_mappings(kc_client, "app")
    email = next(p for p in payloads if p["name"].endswith("standard-email"))
    assert "email_verified" not in email["expression"]
    assert email["expression"] == "return {'email': user.email}"
    assert {e["name"] for e in unmapped} == {"email_verified"}
