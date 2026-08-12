"""migrate_idps against a fake Authentik (in-memory, HTTP-shaped like the
real API -- confirmed live against authentik 2024.10.5's OpenAPI schema and
by creating real sources/certificatekeypairs during task-4) and a Keycloak
client fed from the real fixtures in tests/fixtures/, captured from a live
Keycloak 25 instance seeded with deploy/keycloak/realm-kc2ak-test.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from kc2ak.authentik_client import AuthentikClient
from kc2ak.keycloak_client import KeycloakClient
from kc2ak.mappers.idps import (
    IDP_FLOW_MISSING,
    IDP_SECRET_MISSING,
    IDP_TYPE_UNSUPPORTED,
    MASKED_SECRET,
)
from kc2ak.migrator import (
    API_REJECTED,
    CONFLICT,
    CREATED,
    FAILED,
    SKIPPED,
    UPDATED,
    migrate_idps,
)

FIXTURES = Path(__file__).parent / "fixtures"
REALM = "kc2ak-test"
FLOW_SLUG = "pre-auth-flow"
FLOW_PK = "44444444-0000-0000-0000-000000000001"
AUTH_FLOW_SLUG = "auth-flow"
AUTH_FLOW_PK = "44444444-0000-0000-0000-000000000002"
ENROLL_FLOW_SLUG = "enroll-flow"
ENROLL_FLOW_PK = "44444444-0000-0000-0000-000000000003"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def _idps_fixture() -> list[dict[str, Any]]:
    return list(_load("kc_idps.json"))


def _mappers_fixture(alias: str) -> list[dict[str, Any]]:
    name = alias.replace("-", "_")
    return list(_load(f"kc_idp_mappers_{name}.json"))


def _kc_client(idps: list[dict[str, Any]]) -> KeycloakClient:
    mappers_by_alias = {idp["alias"]: _mappers_fixture(idp["alias"]) for idp in idps}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "kc-token"})
        first = int(request.url.params.get("first", "0"))
        max_ = int(request.url.params.get("max", "100"))
        if path.endswith("/mappers"):
            alias = path.split("/instances/")[1].split("/mappers")[0]
            return httpx.Response(200, json=mappers_by_alias.get(alias, []))
        if path.endswith("/identity-provider/instances"):
            return httpx.Response(200, json=idps[first : first + max_])
        raise AssertionError(f"unexpected Keycloak request: {path}")

    client = KeycloakClient(
        "http://kc.example",
        realm_admin="admin",
        admin_password="admin-pw",
        transport=httpx.MockTransport(handler),
    )
    client.authenticate()
    return client


class FakeAuthentikSources:
    """In-memory stand-in for the sources/certificatekeypairs/flows subset of
    Authentik's API, same shapes confirmed live against authentik 2024.10.5
    in task-4 (created real OAuth/SAML sources and a CertificateKeyPair via
    curl before writing this fake).
    """

    def __init__(self) -> None:
        self.sources: dict[str, dict[str, Any]] = {}  # slug -> record
        self.keypairs: dict[str, dict[str, Any]] = {}  # name -> record
        self.flows = {
            FLOW_SLUG: FLOW_PK,
            AUTH_FLOW_SLUG: AUTH_FLOW_PK,
            ENROLL_FLOW_SLUG: ENROLL_FLOW_PK,
        }
        self._seq = 0
        self.create_oauth_calls = 0
        self.create_saml_calls = 0
        self.update_oauth_calls = 0
        self.update_saml_calls = 0
        self.create_keypair_calls = 0

    def _new_pk(self) -> str:
        self._seq += 1
        return f"src-{self._seq}"

    def seed_source(self, slug: str) -> str:
        pk = self._new_pk()
        self.sources[slug] = {"pk": pk, "slug": slug}
        return pk

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        if path == "/api/v3/flows/instances/" and method == "GET":
            slug = request.url.params.get("slug")
            pk = self.flows.get(slug or "")
            results = [{"pk": pk, "slug": slug}] if pk else []
            return httpx.Response(200, json={"results": results})

        if path == "/api/v3/sources/all/" and method == "GET":
            slug = request.url.params.get("slug")
            results = [self.sources[slug]] if slug in self.sources else []
            return httpx.Response(200, json={"results": results})

        if path == "/api/v3/sources/oauth/" and method == "POST":
            self.create_oauth_calls += 1
            body = json.loads(request.content)
            pk = self._new_pk()
            record = {"pk": pk, **body}
            self.sources[body["slug"]] = record
            return httpx.Response(201, json=record)

        if path == "/api/v3/sources/saml/" and method == "POST":
            self.create_saml_calls += 1
            body = json.loads(request.content)
            pk = self._new_pk()
            record = {"pk": pk, **body}
            self.sources[body["slug"]] = record
            return httpx.Response(201, json=record)

        if path.startswith("/api/v3/sources/oauth/") and method == "PATCH":
            self.update_oauth_calls += 1
            slug = path.removeprefix("/api/v3/sources/oauth/").removesuffix("/")
            body = json.loads(request.content)
            record = self.sources.setdefault(slug, {"pk": self._new_pk(), "slug": slug})
            record.update(body)
            return httpx.Response(200, json=record)

        if path.startswith("/api/v3/sources/saml/") and method == "PATCH":
            self.update_saml_calls += 1
            slug = path.removeprefix("/api/v3/sources/saml/").removesuffix("/")
            body = json.loads(request.content)
            record = self.sources.setdefault(slug, {"pk": self._new_pk(), "slug": slug})
            record.update(body)
            return httpx.Response(200, json=record)

        if path == "/api/v3/crypto/certificatekeypairs/" and method == "GET":
            name = request.url.params.get("name")
            results = [self.keypairs[name]] if name in self.keypairs else []
            return httpx.Response(200, json={"results": results})

        if path == "/api/v3/crypto/certificatekeypairs/" and method == "POST":
            self.create_keypair_calls += 1
            body = json.loads(request.content)
            pk = self._new_pk()
            record = {"pk": pk, "name": body["name"]}
            self.keypairs[body["name"]] = record
            return httpx.Response(201, json=record)

        raise AssertionError(f"unexpected Authentik request: {method} {path}")


def _ak_client(fake: FakeAuthentikSources) -> AuthentikClient:
    return AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(fake.handler)
    )


# --- whitelist / unsupported --------------------------------------------------


def test_unsupported_type_is_conflict_and_writes_nothing() -> None:
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "linkedin-sso"]
    kc = _kc_client(idps)  # linkedin-openid-connect -- outside the whitelist
    results = migrate_idps(kc, _ak_client(fake), REALM, apply=True)
    linkedin = next(r for r in results if r.keycloak_ref == "linkedin-sso")
    assert linkedin.outcome == CONFLICT
    assert linkedin.reason == IDP_TYPE_UNSUPPORTED
    assert linkedin.unmapped[-1]["type"] == IDP_TYPE_UNSUPPORTED
    assert linkedin.unmapped[-1]["name"] == "linkedin-openid-connect"
    assert fake.create_oauth_calls == 0
    assert fake.create_saml_calls == 0
    assert "linkedin-sso" not in fake.sources


def test_oauth_provider_created_with_secret_supplied() -> None:
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(
        kc,
        _ak_client(fake),
        REALM,
        apply=True,
        secrets={"corporate-sso": "the-real-secret"},
        authentication_flow=AUTH_FLOW_SLUG,
        enrollment_flow=ENROLL_FLOW_SLUG,
    )
    assert len(results) == 1
    result = results[0]
    assert result.outcome == CREATED
    assert not any(u["type"] == IDP_SECRET_MISSING for u in result.unmapped)
    assert not any(u["type"] == IDP_FLOW_MISSING for u in result.unmapped)
    created = fake.sources["corporate-sso"]
    assert created["enabled"] is True
    assert created["consumer_secret"] == "the-real-secret"
    assert created["provider_type"] == "openidconnect"
    assert created["authentication_flow"] == AUTH_FLOW_PK
    assert created["enrollment_flow"] == ENROLL_FLOW_PK


def test_oauth_provider_created_disabled_without_flows_even_with_secret() -> None:
    # task-5b: authentication_flow/enrollment_flow are optional flags, but
    # their absence still disables the source -- same user-visible failure
    # class as a missing secret (.chief/milestone-2/_goal/02-identity-providers.md).
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(
        kc, _ak_client(fake), REALM, apply=True, secrets={"corporate-sso": "the-real-secret"}
    )
    assert results[0].outcome == CREATED
    assert not any(u["type"] == IDP_SECRET_MISSING for u in results[0].unmapped)
    assert any(u["type"] == IDP_FLOW_MISSING for u in results[0].unmapped)
    created = fake.sources["corporate-sso"]
    assert created["enabled"] is False


def test_oauth_provider_flow_missing_reported_the_same_on_a_dry_run() -> None:
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(
        kc, _ak_client(fake), REALM, apply=False, secrets={"corporate-sso": "the-real-secret"}
    )
    assert results[0].outcome == CREATED
    assert any(u["type"] == IDP_FLOW_MISSING for u in results[0].unmapped)
    assert fake.create_oauth_calls == 0


def test_saml_provider_created_with_signing_kp_from_real_certificate() -> None:
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-saml"]
    kc = _kc_client(idps)
    results = migrate_idps(
        kc, _ak_client(fake), REALM, apply=True, pre_authentication_flow=FLOW_SLUG
    )
    assert len(results) == 1
    assert results[0].outcome == CREATED
    created = fake.sources["corporate-saml"]
    assert created["enabled"] is True
    assert created["pre_authentication_flow"] == FLOW_PK
    assert fake.create_keypair_calls == 1
    kp_name = next(iter(fake.keypairs))
    assert created["signing_kp"] == fake.keypairs[kp_name]["pk"]


# --- secret presence / masking ------------------------------------------------


def test_oauth_provider_created_disabled_without_secret() -> None:
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(kc, _ak_client(fake), REALM, apply=True, secrets={})
    assert results[0].outcome == CREATED
    assert any(u["type"] == IDP_SECRET_MISSING for u in results[0].unmapped)
    created = fake.sources["corporate-sso"]
    assert created["enabled"] is False
    assert created["consumer_secret"] != ""


def test_disabled_reported_the_same_on_a_dry_run() -> None:
    # The stdout "created disabled" line and the report must agree before
    # --apply, not just after -- same fidelity rule task-3b fixed for
    # dry-run collisions.
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(kc, _ak_client(fake), REALM, apply=False, secrets={})
    assert results[0].outcome == CREATED
    assert any(u["type"] == IDP_SECRET_MISSING for u in results[0].unmapped)
    assert fake.create_oauth_calls == 0  # dry run: nothing written


def test_masked_placeholder_in_secrets_file_is_never_written_as_the_secret() -> None:
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(
        kc, _ak_client(fake), REALM, apply=True, secrets={"corporate-sso": MASKED_SECRET}
    )
    assert any(u["type"] == IDP_SECRET_MISSING for u in results[0].unmapped)
    created = fake.sources["corporate-sso"]
    assert created["enabled"] is False
    assert created["consumer_secret"] != MASKED_SECRET


def test_keycloaks_own_masked_secret_never_reaches_the_payload() -> None:
    # kc_idps.json's corporate-sso config.clientSecret is "**********" --
    # confirm that value is never the source of the written secret, only
    # the --idp-secrets file is.
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    assert idps[0]["config"]["clientSecret"] == MASKED_SECRET
    kc = _kc_client(idps)
    migrate_idps(
        kc, _ak_client(fake), REALM, apply=True, secrets={"corporate-sso": "real-file-secret"}
    )
    assert fake.sources["corporate-sso"]["consumer_secret"] == "real-file-secret"


# --- idp mappers ---------------------------------------------------------------


def test_idp_mappers_reported_unmapped_and_never_translated() -> None:
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(kc, _ak_client(fake), REALM, apply=True, secrets={"corporate-sso": "s"})
    assert results[0].unmapped[0]["type"] == "idp_mapper"
    assert results[0].unmapped[0]["name"] == "department-attribute"


# --- matching / update_existing -----------------------------------------------


def test_existing_source_is_skipped_without_update_existing() -> None:
    fake = FakeAuthentikSources()
    fake.seed_source("corporate-sso")
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(kc, _ak_client(fake), REALM, apply=True, secrets={"corporate-sso": "s"})
    assert results[0].outcome == SKIPPED
    assert fake.create_oauth_calls == 0


def test_skipped_source_without_secret_carries_no_secret_missing_entry() -> None:
    # A SKIPPED match writes nothing -- it must never be tagged
    # idp_secret_missing just because this run's secrets file happens to
    # lack an entry for it. That would misreport an already-enabled,
    # already-working source as inert on every re-run without the file.
    fake = FakeAuthentikSources()
    fake.seed_source("corporate-sso")
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(kc, _ak_client(fake), REALM, apply=True, secrets={})
    assert results[0].outcome == SKIPPED
    assert not any(u["type"] == IDP_SECRET_MISSING for u in results[0].unmapped)


def test_bogus_pre_authentication_flow_is_harmless_without_a_saml_idp() -> None:
    # preconditions only validate --pre-authentication-flow when a SAML IdP
    # is actually in scope; migrate_idps must not eagerly resolve it either,
    # or a bogus/unused flag on an OAuth-only run would crash instead of
    # being quietly unused.
    fake = FakeAuthentikSources()
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(
        kc,
        _ak_client(fake),
        REALM,
        apply=True,
        secrets={"corporate-sso": "s"},
        pre_authentication_flow="this-flow-does-not-exist",
    )
    assert results[0].outcome == CREATED


def test_existing_source_is_updated_under_update_existing() -> None:
    fake = FakeAuthentikSources()
    fake.seed_source("corporate-sso")
    idps = [i for i in _idps_fixture() if i["alias"] == "corporate-sso"]
    kc = _kc_client(idps)
    results = migrate_idps(
        kc,
        _ak_client(fake),
        REALM,
        apply=True,
        update_existing=True,
        secrets={"corporate-sso": "s"},
    )
    assert results[0].outcome == UPDATED
    assert fake.update_oauth_calls == 1
    assert fake.create_oauth_calls == 0


# --- failure isolation ---------------------------------------------------------


def test_api_rejection_is_failed_and_run_continues() -> None:
    class RejectingFake(FakeAuthentikSources):
        def handler(self, request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/v3/sources/oauth/" and request.method == "POST":
                return httpx.Response(400, json={"non_field_errors": ["nope"]})
            return super().handler(request)

    fake = RejectingFake()
    idps = _idps_fixture()  # corporate-sso (oauth) + corporate-saml (saml) + linkedin (conflict)
    kc = _kc_client(idps)
    results = migrate_idps(
        kc,
        _ak_client(fake),
        REALM,
        apply=True,
        secrets={"corporate-sso": "s"},
        pre_authentication_flow=FLOW_SLUG,
    )
    by_alias = {r.keycloak_ref: r for r in results}
    assert by_alias["corporate-sso"].outcome == FAILED
    assert by_alias["corporate-sso"].reason == API_REJECTED
    # The rest of the run still completed.
    assert by_alias["corporate-saml"].outcome == CREATED
    assert by_alias["linkedin-sso"].outcome == CONFLICT
