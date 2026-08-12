"""migrate_federated_links against a fake Keycloak (users + federated-identity)
and a fake Authentik (sources only) -- covers the "authentik's API cannot
pre-create these links" pivot. See the "Federated identity links" amendment
in .chief/milestone-2/_contract/02-idp-mapping.md: nothing is written here,
so these tests are about what gets *counted* and *reported*, not what gets
created.
"""

from __future__ import annotations

from typing import Any

import httpx

from kc2ak.authentik_client import AuthentikClient
from kc2ak.keycloak_client import KeycloakClient
from kc2ak.mappers.idps import FEDERATED_LINK_SOURCE_MISSING, FEDERATED_LINK_UNWRITABLE
from kc2ak.migrator import CONFLICT, CREATED, EntityResult, migrate_federated_links

REALM = "kc2ak-test"

ALICE = {"id": "u1", "username": "alice"}
BOB = {"id": "u2", "username": "bob"}


def _kc_client(
    users: list[dict[str, Any]], federated_by_user: dict[str, list[dict[str, Any]]]
) -> KeycloakClient:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "kc-token"})
        first = int(request.url.params.get("first", "0"))
        max_ = int(request.url.params.get("max", "100"))
        if path.endswith("/users"):
            return httpx.Response(200, json=users[first : first + max_])
        if path.endswith("/federated-identity"):
            uid = path.split("/users/")[1].split("/federated-identity")[0]
            return httpx.Response(200, json=federated_by_user.get(uid, []))
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
    """Only sources/all/ -- migrate_federated_links never writes anything."""

    def __init__(self) -> None:
        self.sources: dict[str, dict[str, Any]] = {}

    def seed_source(self, slug: str) -> None:
        self.sources[slug] = {"pk": f"src-{slug}", "slug": slug}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v3/sources/all/" and request.method == "GET":
            slug = request.url.params.get("slug")
            results = [self.sources[slug]] if slug in self.sources else []
            return httpx.Response(200, json={"results": results})
        raise AssertionError(f"unexpected Authentik request: {request.method} {path}")


def _ak_client(fake: FakeAuthentikSources) -> AuthentikClient:
    return AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(fake.handler)
    )


def _link(alias: str, user_id: str = "ext-1") -> dict[str, str]:
    return {"identityProvider": alias, "userId": user_id, "userName": "someone"}


# --- resolved source (this run) -> no entity, one aggregated unmapped note ----


def test_resolved_source_this_run_emits_no_entity_and_tags_the_source() -> None:
    kc = _kc_client([ALICE], {"u1": [_link("corporate-sso")]})
    idp_results = [EntityResult("idp", "i1", "corporate-sso", "src-pk", CREATED)]
    results = migrate_federated_links(
        kc,
        _ak_client(FakeAuthentikSources()),
        REALM,
        idp_results=idp_results,
        user_matching_mode="username_link",
    )
    assert results == []
    assert idp_results[0].unmapped == [
        {
            "type": FEDERATED_LINK_UNWRITABLE,
            "name": "corporate-sso",
            "why": (
                "1 Keycloak user(s) hold a federated identity to this source; "
                "authentik cannot pre-create the link, user_matching_mode="
                "username_link was set instead"
            ),
        }
    ]


def test_counts_every_user_linked_to_the_same_source() -> None:
    kc = _kc_client(
        [ALICE, BOB],
        {"u1": [_link("corporate-sso", "ext-1")], "u2": [_link("corporate-sso", "ext-2")]},
    )
    idp_results = [EntityResult("idp", "i1", "corporate-sso", "src-pk", CREATED)]
    results = migrate_federated_links(
        kc,
        _ak_client(FakeAuthentikSources()),
        REALM,
        idp_results=idp_results,
        user_matching_mode="email_link",
    )
    assert results == []
    assert "2 Keycloak user(s)" in idp_results[0].unmapped[0]["why"]
    assert "user_matching_mode=email_link" in idp_results[0].unmapped[0]["why"]


# --- source not migrated at all -> per-user CONFLICT --------------------------


def test_conflicted_idp_this_run_is_source_missing_per_user() -> None:
    kc = _kc_client([ALICE], {"u1": [_link("linkedin-sso")]})
    idp_results = [
        EntityResult("idp", "i1", "linkedin-sso", None, CONFLICT, "idp_type_unsupported")
    ]
    results = migrate_federated_links(
        kc,
        _ak_client(FakeAuthentikSources()),
        REALM,
        idp_results=idp_results,
        user_matching_mode="username_link",
    )
    assert len(results) == 1
    assert results[0].kind == "federated_link"
    assert results[0].keycloak_ref == "alice/linkedin-sso"
    assert results[0].outcome == CONFLICT
    assert results[0].reason == FEDERATED_LINK_SOURCE_MISSING
    # Never tagged unwritable -- the source never resolved at all.
    assert idp_results[0].unmapped == []


def test_idps_out_of_scope_and_no_live_source_is_source_missing() -> None:
    kc = _kc_client([ALICE], {"u1": [_link("corporate-sso")]})
    results = migrate_federated_links(
        kc,
        _ak_client(FakeAuthentikSources()),
        REALM,
        idp_results=[],
        user_matching_mode="username_link",
    )
    assert len(results) == 1
    assert results[0].reason == FEDERATED_LINK_SOURCE_MISSING


def test_idps_out_of_scope_but_source_exists_live_is_not_reported_missing() -> None:
    # "federated-links without idps in scope is legitimate: the sources may
    # already exist from an earlier run" (03-cli-and-report-extensions.md).
    # There is no idp entity from *this* run to attach a count to, so
    # nothing is emitted at all -- an earlier run's idp entity already
    # carried the note.
    fake = FakeAuthentikSources()
    fake.seed_source("corporate-sso")
    kc = _kc_client([ALICE], {"u1": [_link("corporate-sso")]})
    results = migrate_federated_links(
        kc, _ak_client(fake), REALM, idp_results=[], user_matching_mode="username_link"
    )
    assert results == []


# --- no links -> nothing -------------------------------------------------------


def test_user_with_no_federated_identities_produces_nothing() -> None:
    kc = _kc_client([ALICE], {"u1": []})
    idp_results = [EntityResult("idp", "i1", "corporate-sso", "src-pk", CREATED)]
    results = migrate_federated_links(
        kc,
        _ak_client(FakeAuthentikSources()),
        REALM,
        idp_results=idp_results,
        user_matching_mode="username_link",
    )
    assert results == []
    assert idp_results[0].unmapped == []
