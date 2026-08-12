"""Fixture-backed tests for the identity-provider mapper.
tests/fixtures/kc_idps.json is a real GET
/admin/realms/{realm}/identity-provider/instances response, and
kc_idp_mappers_*.json are real GET .../instances/{alias}/mappers responses,
both captured from a live Keycloak 25 instance seeded from
deploy/keycloak/realm-kc2ak-test.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kc2ak.mappers.idps import (
    MASKED_SECRET,
    PLACEHOLDER_SECRET,
    map_oauth_source,
    map_saml_source,
    pem_certificate,
    resolved_secret,
    source_kind,
    unmapped_idp_mappers,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _idps() -> dict[str, dict[str, Any]]:
    data = json.loads((FIXTURES / "kc_idps.json").read_text())
    return {i["alias"]: i for i in data}


def _mappers(alias: str) -> list[dict[str, Any]]:
    name = alias.replace("-", "_")
    return list(json.loads((FIXTURES / f"kc_idp_mappers_{name}.json").read_text()))


# --- source_kind / whitelist -------------------------------------------------


def test_source_kind_covers_the_whole_whitelist() -> None:
    oauth_types = (
        "oidc",
        "keycloak-oidc",
        "google",
        "github",
        "gitlab",
        "facebook",
        "twitter",
        "okta",
        "apple",
        "discord",
        "reddit",
        "twitch",
        "microsoft",
    )
    for provider_id in oauth_types:
        assert source_kind(provider_id) == "oauth", provider_id
    assert source_kind("saml") == "saml"


def test_source_kind_rejects_unwhitelisted_linkedin() -> None:
    # linkedin-openid-connect, not "linkedin" -- see the contract's
    # task-1 amendment for why.
    assert source_kind("linkedin-openid-connect") is None
    assert source_kind("bitbucket") is None
    assert source_kind("linkedin") is None


def test_seeded_linkedin_provider_is_unsupported() -> None:
    idp = _idps()["linkedin-sso"]
    assert source_kind(idp["providerId"]) is None


# --- resolved_secret ---------------------------------------------------------


def test_resolved_secret_present() -> None:
    assert resolved_secret("corporate-sso", {"corporate-sso": "s3cr3t"}) == "s3cr3t"


def test_resolved_secret_absent_when_missing_from_file() -> None:
    assert resolved_secret("corporate-sso", {}) is None


def test_resolved_secret_absent_when_masked_placeholder_pasted() -> None:
    # An operator pasting Keycloak's own masked value in by mistake must
    # never be treated as a working secret.
    assert resolved_secret("corporate-sso", {"corporate-sso": MASKED_SECRET}) is None


# --- map_oauth_source ---------------------------------------------------------


def test_map_oauth_source_enabled_with_secret() -> None:
    idp = _idps()["corporate-sso"]
    payload = map_oauth_source(idp, secret="the-real-secret")
    assert payload["name"] == "corporate-sso"
    assert payload["slug"] == "corporate-sso"
    assert payload["provider_type"] == "openidconnect"
    assert payload["consumer_key"] == "kc2ak-test-oidc-client"
    assert payload["consumer_secret"] == "the-real-secret"
    assert payload["enabled"] is True
    assert payload["authorization_url"] == idp["config"]["authorizationUrl"]
    assert payload["access_token_url"] == idp["config"]["tokenUrl"]
    assert payload["profile_url"] == idp["config"]["userInfoUrl"]
    assert "oidc_well_known_url" not in payload  # no `issuer` in this fixture


def test_map_oauth_source_disabled_without_secret() -> None:
    idp = _idps()["corporate-sso"]
    payload = map_oauth_source(idp, secret=None)
    assert payload["consumer_secret"] == PLACEHOLDER_SECRET
    assert payload["enabled"] is False


def test_map_oauth_source_maps_issuer_to_oidc_well_known_url_when_present() -> None:
    # Not exercised by the live seed (task-4 removed the fake `issuer`
    # placeholder so the live login check isn't sent through discovery) --
    # tested here against a synthetic config, same as test_mappers_clients.py's
    # "saml-app" case for a shape not present live.
    idp = {
        "alias": "with-issuer",
        "providerId": "oidc",
        "config": {"clientId": "c", "issuer": "https://issuer.example.com"},
    }
    payload = map_oauth_source(idp, secret="s")
    assert payload["oidc_well_known_url"] == "https://issuer.example.com"


def test_map_oauth_source_omits_urls_absent_from_a_social_providers_config() -> None:
    # linkedin-sso's config carries no authorizationUrl/tokenUrl/userInfoUrl
    # -- a known built-in social provider relies on authentik's own baked-in
    # endpoints for its provider_type, confirmed live: authentik only 400s
    # on a missing authorization_url for "openidconnect" specifically.
    idp = _idps()["linkedin-sso"]
    payload = map_oauth_source({**idp, "providerId": "github"}, secret="s")
    assert "authorization_url" not in payload
    assert "access_token_url" not in payload
    assert "profile_url" not in payload


# --- pem_certificate / map_saml_source ---------------------------------------


def test_pem_certificate_wraps_bare_base64_der() -> None:
    idp = _idps()["corporate-saml"]
    der = idp["config"]["signingCertificate"]
    pem = pem_certificate(der)
    assert pem.startswith("-----BEGIN CERTIFICATE-----\n")
    assert pem.endswith("-----END CERTIFICATE-----\n")
    assert der in pem.replace("\n", "")


def test_map_saml_source_fields() -> None:
    idp = _idps()["corporate-saml"]
    payload = map_saml_source(idp, pre_authentication_flow="flow-pk", signing_kp="kp-pk")
    assert payload["name"] == "corporate-saml"
    assert payload["slug"] == "corporate-saml"
    assert payload["sso_url"] == idp["config"]["singleSignOnServiceUrl"]
    assert payload["slo_url"] == idp["config"]["singleLogoutServiceUrl"]
    assert payload["issuer"] == idp["config"]["idpEntityId"]
    assert payload["pre_authentication_flow"] == "flow-pk"
    assert payload["signing_kp"] == "kp-pk"
    assert payload["enabled"] is True  # SAML needs no secret -- always enabled


def test_map_saml_source_omits_signing_kp_when_none() -> None:
    idp = _idps()["corporate-saml"]
    payload = map_saml_source(idp, pre_authentication_flow="flow-pk", signing_kp=None)
    assert "signing_kp" not in payload


# --- unmapped_idp_mappers -----------------------------------------------------


def test_unmapped_idp_mappers_reports_the_seeded_mapper() -> None:
    unmapped = unmapped_idp_mappers(_mappers("corporate-sso"))
    assert unmapped == [
        {
            "type": "idp_mapper",
            "name": "department-attribute",
            "why": "IdP mappers are not translated",
        }
    ]


def test_unmapped_idp_mappers_empty_when_none() -> None:
    assert unmapped_idp_mappers(_mappers("corporate-saml")) == []
    assert unmapped_idp_mappers([]) == []
