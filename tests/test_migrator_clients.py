"""migrate_clients against a fake Authentik (in-memory, HTTP-shaped like the
real API -- endpoints and payload shapes confirmed live in task-5a's
verification pass, including that authorization_flow/invalidation_flow
require the flow's pk, not its slug) and a Keycloak client fed from the real
fixture tests/fixtures/kc_clients.json, captured from a live Keycloak 25
seeded with deploy/keycloak/realm-kc2ak-test.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from kc2ak import redact as redact_mod
from kc2ak.authentik_client import AuthentikClient
from kc2ak.keycloak_client import KeycloakClient
from kc2ak.migrator import (
    API_REJECTED,
    CREATED,
    FAILED,
    SKIPPED,
    UPDATED,
    migrate_clients,
)
from kc2ak.report import build_report, compute_recovery_mail, write_report

FIXTURES = Path(__file__).parent / "fixtures"

AUTH_FLOW_SLUG = "auth-flow"
INV_FLOW_SLUG = "inv-flow"
AUTH_FLOW_PK = "11111111-aaaa-0000-0000-000000000001"
INV_FLOW_PK = "22222222-bbbb-0000-0000-000000000002"


def _load_clients() -> list[dict[str, Any]]:
    return list(json.loads((FIXTURES / "kc_clients.json").read_text()))


def _kc_client(
    *, clients: list[dict[str, Any]] | None = None, secrets: dict[str, str] | None = None
) -> KeycloakClient:
    clients = clients or []
    secrets = secrets or {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "kc-token"})
        first = int(request.url.params.get("first", "0"))
        max_ = int(request.url.params.get("max", "100"))
        if path.endswith("/clients"):
            return httpx.Response(200, json=clients[first : first + max_])
        if path.endswith("/client-secret"):
            kc_id = path.split("/clients/")[1].split("/client-secret")[0]
            return httpx.Response(200, json={"type": "secret", "value": secrets[kc_id]})
        raise AssertionError(f"unexpected Keycloak request: {path}")

    client = KeycloakClient(
        "http://kc.example",
        realm_admin="admin",
        admin_password="admin-pw",
        transport=httpx.MockTransport(handler),
    )
    client.authenticate()
    return client


class FakeAuthentikClients:
    """In-memory stand-in for the subset of Authentik's API migrate_clients
    touches: flow lookup, OAuth2Provider, Application. Shapes confirmed
    live against authentik 2024.10.5 in task-5a's verification pass.
    """

    def __init__(self) -> None:
        self.flows = {AUTH_FLOW_SLUG: AUTH_FLOW_PK, INV_FLOW_SLUG: INV_FLOW_PK}
        self.providers: dict[int, dict[str, Any]] = {}
        self.applications: dict[str, dict[str, Any]] = {}
        self.scope_mappings: dict[str, dict[str, Any]] = {}
        self._provider_seq = 0
        self._scope_mapping_seq = 0
        self.create_provider_calls = 0
        self.update_provider_calls = 0
        self.create_application_calls = 0
        self.create_scope_mapping_calls = 0
        self.find_scope_mapping_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        if path == "/api/v3/flows/instances/" and method == "GET":
            slug = request.url.params.get("slug")
            pk = self.flows.get(slug or "")
            results = [{"pk": pk, "slug": slug}] if pk else []
            return httpx.Response(200, json={"pagination": {}, "results": results})

        if path == "/api/v3/providers/oauth2/" and method == "GET":
            client_id = request.url.params.get("client_id")
            results = [p for p in self.providers.values() if p["client_id"] == client_id]
            return httpx.Response(200, json={"pagination": {}, "results": results})

        if path == "/api/v3/providers/oauth2/" and method == "POST":
            self.create_provider_calls += 1
            body = json.loads(request.content)
            self._provider_seq += 1
            record = {"pk": self._provider_seq, **body}
            self.providers[self._provider_seq] = record
            return httpx.Response(201, json=record)

        if path.startswith("/api/v3/providers/oauth2/") and method == "PATCH":
            self.update_provider_calls += 1
            pk = int(path.removeprefix("/api/v3/providers/oauth2/").removesuffix("/"))
            provider = self.providers.get(pk)
            if provider is None:
                return httpx.Response(404, json={"detail": "not found"})
            body = json.loads(request.content)
            provider.update(body)
            return httpx.Response(200, json=provider)

        if path == "/api/v3/core/applications/" and method == "GET":
            slug = request.url.params.get("slug")
            results = [a for a in self.applications.values() if a["slug"] == slug]
            return httpx.Response(200, json={"pagination": {}, "results": results})

        if path == "/api/v3/core/applications/" and method == "POST":
            self.create_application_calls += 1
            body = json.loads(request.content)
            record = {**body}
            self.applications[body["slug"]] = record
            return httpx.Response(201, json=record)

        if path == "/api/v3/propertymappings/provider/scope/" and method == "GET":
            self.find_scope_mapping_calls += 1
            name = request.url.params.get("name")
            existing = self.scope_mappings.get(name or "")
            results = [existing] if existing else []
            return httpx.Response(200, json={"pagination": {}, "results": results})

        if path == "/api/v3/propertymappings/provider/scope/" and method == "POST":
            self.create_scope_mapping_calls += 1
            body = json.loads(request.content)
            if body["name"] in self.scope_mappings:
                return httpx.Response(
                    400, json={"name": ["Property Mapping with this name already exists."]}
                )
            self._scope_mapping_seq += 1
            pk = f"mapping-{self._scope_mapping_seq}"
            record = {"pk": pk, **body}
            self.scope_mappings[body["name"]] = record
            return httpx.Response(201, json=record)

        raise AssertionError(f"unexpected Authentik request: {method} {path}")


def _ak_client(fake: FakeAuthentikClients) -> AuthentikClient:
    return AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(fake.handler)
    )


def setup_function() -> None:
    redact_mod._secrets.clear()


def _confidential_app_client() -> dict[str, Any]:
    clients = {c["clientId"]: c for c in _load_clients()}
    return clients["confidential-app"]


def _run(
    fake: FakeAuthentikClients,
    clients: list[dict[str, Any]],
    *,
    apply: bool,
    update_existing: bool = False,
    secrets: dict[str, str] | None = None,
) -> list[Any]:
    kc = _kc_client(clients=clients, secrets=secrets or {})
    return migrate_clients(
        kc,
        _ak_client(fake),
        "kc2ak-test",
        apply=apply,
        authorization_flow=AUTH_FLOW_SLUG,
        invalidation_flow=INV_FLOW_SLUG,
        update_existing=update_existing,
    )


# --- built-ins are filtered out entirely ------------------------------------


def test_builtin_and_non_oidc_clients_never_become_entities() -> None:
    fake = FakeAuthentikClients()
    results = _run(
        fake,
        _load_clients(),  # includes account/admin-cli/etc alongside confidential-app
        apply=True,
        secrets={"33333333-0000-0000-0000-000000000001": "kc2ak-test-client-secret"},
    )
    assert len(results) == 1
    assert results[0].keycloak_ref == "confidential-app"
    assert fake.create_provider_calls == 1


# --- create ------------------------------------------------------------


def test_migrate_clients_creates_provider_and_application_under_apply() -> None:
    fake = FakeAuthentikClients()
    kc_client = _confidential_app_client()
    results = _run(
        fake,
        [kc_client],
        apply=True,
        secrets={kc_client["id"]: "kc2ak-test-client-secret"},
    )

    assert len(results) == 1
    result = results[0]
    assert result.outcome == CREATED
    assert result.authentik_ref == "confidential-app"
    assert fake.create_provider_calls == 1
    assert fake.create_application_calls == 1

    provider = next(iter(fake.providers.values()))
    assert provider["client_id"] == "confidential-app"
    assert provider["client_type"] == "confidential"
    assert provider["client_secret"] == "kc2ak-test-client-secret"
    assert provider["authorization_flow"] == AUTH_FLOW_PK  # resolved from slug, not the slug itself
    assert provider["invalidation_flow"] == INV_FLOW_PK

    app = fake.applications["confidential-app"]
    assert app["provider"] == provider["pk"]


def test_migrate_clients_reports_unmapped_fields_and_stays_created() -> None:
    fake = FakeAuthentikClients()
    kc_client = _confidential_app_client()
    results = _run(
        fake, [kc_client], apply=True, secrets={kc_client["id"]: "kc2ak-test-client-secret"}
    )
    result = results[0]
    assert result.outcome == CREATED  # unmapped never downgrades the outcome
    names = {e["name"] for e in result.unmapped}
    assert "webOrigins" in names
    assert "standardFlowEnabled" in names
    assert "defaultClientScopes" in names


# --- protocol mapper whitelist (task-5b) ------------------------------------


def test_migrate_clients_creates_and_attaches_scope_mappings_under_apply() -> None:
    fake = FakeAuthentikClients()
    kc_client = _confidential_app_client()
    results = _run(
        fake, [kc_client], apply=True, secrets={kc_client["id"]: "kc2ak-test-client-secret"}
    )

    # 7 of confidential-app's 8 fixture mappers are whitelisted-type
    # instances (realm-roles is the one outside the whitelist), plus 3
    # standard-scope copies (openid always; profile/email are both in the
    # fixture's defaultClientScopes -- task-5c).
    assert fake.create_scope_mapping_calls == 10
    provider = next(iter(fake.providers.values()))
    assert len(provider["property_mappings"]) == 10
    assert set(provider["property_mappings"]) == {m["pk"] for m in fake.scope_mappings.values()}
    standard_names = {
        "kc2ak: confidential-app / standard-openid",
        "kc2ak: confidential-app / standard-profile",
        "kc2ak: confidential-app / standard-email",
    }
    assert standard_names <= {m["name"] for m in fake.scope_mappings.values()}
    mapping_names = {m["name"] for m in fake.scope_mappings.values()}
    assert "kc2ak: confidential-app / username" in mapping_names
    username_mapping = next(
        m for m in fake.scope_mappings.values() if m["name"] == "kc2ak: confidential-app / username"
    )
    assert username_mapping["expression"] == "return {'preferred_username': user.username}"
    assert username_mapping["scope_name"] == "openid"

    result = results[0]
    unmapped_types = {e["mapper_type"] for e in result.unmapped if e["type"] == "protocol_mapper"}
    assert unmapped_types == {"oidc-usermodel-realm-role-mapper"}


def test_migrate_clients_groups_claim_appears_in_exactly_one_created_mapping() -> None:
    # task-5d regression pin: confidential-app has both a translated
    # oidc-group-membership-mapper (whitelist) and "profile" in its
    # defaultClientScopes. Before task-5d, the standard-profile copy also
    # emitted "groups", and authentik concatenates same-key list values
    # across mappings rather than overwriting, so the group would have been
    # listed twice in the issued token. Exactly one created ScopeMapping may
    # reference the groups claim.
    fake = FakeAuthentikClients()
    kc_client = _confidential_app_client()
    _run(fake, [kc_client], apply=True, secrets={kc_client["id"]: "kc2ak-test-client-secret"})

    groups_mappings = [m for m in fake.scope_mappings.values() if "'groups'" in m["expression"]]
    assert len(groups_mappings) == 1
    assert groups_mappings[0]["name"] == "kc2ak: confidential-app / groups"
    standard_profile = next(
        m
        for m in fake.scope_mappings.values()
        if m["name"] == "kc2ak: confidential-app / standard-profile"
    )
    assert "groups" not in standard_profile["expression"]


def test_migrate_clients_dry_run_reports_unmapped_mapper_without_creating_any() -> None:
    fake = FakeAuthentikClients()
    kc_client = _confidential_app_client()
    results = _run(
        fake, [kc_client], apply=False, secrets={kc_client["id"]: "kc2ak-test-client-secret"}
    )

    assert fake.create_scope_mapping_calls == 0
    result = results[0]
    assert result.outcome == CREATED
    unmapped_types = {e["mapper_type"] for e in result.unmapped if e["type"] == "protocol_mapper"}
    assert unmapped_types == {"oidc-usermodel-realm-role-mapper"}


def test_migrate_clients_skipped_match_never_creates_scope_mappings() -> None:
    # A matched (SKIPPED) provider must not re-attempt mapper creation --
    # ScopeMapping.name is globally unique, so a second attempt would 400.
    fake = FakeAuthentikClients()
    fake.providers[1] = {
        "pk": 1,
        "client_id": "confidential-app",
        "client_type": "confidential",
    }
    fake.applications["confidential-app"] = {"slug": "confidential-app", "provider": 1}
    kc_client = _confidential_app_client()

    results = _run(
        fake, [kc_client], apply=True, secrets={kc_client["id"]: "kc2ak-test-client-secret"}
    )

    assert results[0].outcome == SKIPPED
    assert fake.create_scope_mapping_calls == 0
    # unmapped is still reported on a SKIPPED match -- it's a property of
    # what was read from Keycloak, not of whether anything was written.
    unmapped_types = {
        e["mapper_type"] for e in results[0].unmapped if e["type"] == "protocol_mapper"
    }
    assert unmapped_types == {"oidc-usermodel-realm-role-mapper"}


def test_migrate_clients_scope_mapping_create_failure_marks_client_failed() -> None:
    fake = FakeAuthentikClients()

    def failing_mapping_handler(request: httpx.Request) -> httpx.Response:
        if (
            request.url.path == "/api/v3/propertymappings/provider/scope/"
            and request.method == "POST"
        ):
            return httpx.Response(500, json={"detail": "boom"})
        return fake.handler(request)

    ak = AuthentikClient(
        "http://ak.example", "tok", transport=httpx.MockTransport(failing_mapping_handler)
    )
    kc_client = _confidential_app_client()
    kc = _kc_client(clients=[kc_client], secrets={kc_client["id"]: "kc2ak-test-client-secret"})

    results = migrate_clients(
        kc,
        ak,
        "kc2ak-test",
        apply=True,
        authorization_flow=AUTH_FLOW_SLUG,
        invalidation_flow=INV_FLOW_SLUG,
    )

    assert len(results) == 1
    assert results[0].outcome == FAILED
    assert results[0].reason == API_REJECTED
    assert fake.create_provider_calls == 0  # never reached -- mapper create failed first


def test_migrate_clients_no_protocol_mappers_still_attaches_standard_openid_only() -> None:
    # "openid" is always attached (task-5c), even for a client with no
    # protocol mappers and no defaultClientScopes/optionalClientScopes at
    # all -- profile/email are not, since neither is declared.
    fake = FakeAuthentikClients()
    kc_client = {
        "id": "pub-1",
        "clientId": "no-mappers-app",
        "protocol": "openid-connect",
        "publicClient": True,
        "redirectUris": [],
    }
    _run(fake, [kc_client], apply=True)

    assert fake.create_scope_mapping_calls == 1
    provider = next(iter(fake.providers.values()))
    assert len(provider["property_mappings"]) == 1
    (mapping,) = fake.scope_mappings.values()
    assert mapping["name"] == "kc2ak: no-mappers-app / standard-openid"


def test_unmapped_mapper_forces_exit_code_1_with_outcome_still_created() -> None:
    # The rule most likely to be got wrong per the task brief: an
    # unrecognised protocol mapper is not a CONFLICT (the provider *was*
    # written), but a non-empty `unmapped` anywhere still forces exit 1.
    from kc2ak.report import exit_code

    fake = FakeAuthentikClients()
    kc_client = _confidential_app_client()
    results = _run(
        fake, [kc_client], apply=True, secrets={kc_client["id"]: "kc2ak-test-client-secret"}
    )

    assert results[0].outcome == CREATED
    assert any(e["type"] == "protocol_mapper" for e in results[0].unmapped)
    assert exit_code(results) == 1


def test_migrate_clients_interrupted_between_mapping_and_provider_create_converges_on_rerun() -> (
    None
):
    # task-5c: a run killed after ScopeMapping creation but before the
    # provider POST leaves orphan mappings -- ScopeMapping.name is globally
    # unique, so a plain create on rerun would 400 on every one of them
    # forever. Find-or-create is what makes the rerun converge instead
    # (.chief/milestone-1/_goal/03-idempotency-and-matching.md's
    # "interrupted run completes without duplicates").
    fake = FakeAuthentikClients()
    kc_client = _confidential_app_client()

    # Simulate the interrupted first run: every mapping this client would
    # produce already exists, but no provider/application do.
    from kc2ak.mappers.clients import standard_scope_mappings
    from kc2ak.mappers.protocol_mappers import translate_client_protocol_mappers

    mapper_payloads, _unmapped = translate_client_protocol_mappers(kc_client, "confidential-app")
    standard_payloads, _standard_unmapped = standard_scope_mappings(kc_client, "confidential-app")
    all_payloads = standard_payloads + mapper_payloads
    for payload in all_payloads:
        fake._scope_mapping_seq += 1
        pk = f"mapping-{fake._scope_mapping_seq}"
        fake.scope_mappings[payload["name"]] = {"pk": pk, **payload}

    results = _run(
        fake, [kc_client], apply=True, secrets={kc_client["id"]: "kc2ak-test-client-secret"}
    )

    assert results[0].outcome == CREATED
    assert fake.create_scope_mapping_calls == 0  # every mapping found, none re-created
    assert fake.find_scope_mapping_calls == len(all_payloads)
    provider = next(iter(fake.providers.values()))
    assert len(provider["property_mappings"]) == len(all_payloads)
    assert set(provider["property_mappings"]) == {m["pk"] for m in fake.scope_mappings.values()}


def test_migrate_clients_public_client_has_no_secret_field() -> None:
    fake = FakeAuthentikClients()
    kc_client = {
        "id": "pub-1",
        "clientId": "public-spa",
        "protocol": "openid-connect",
        "publicClient": True,
        "redirectUris": ["https://spa.example.com/callback"],
    }
    _run(fake, [kc_client], apply=True)

    provider = next(iter(fake.providers.values()))
    assert provider["client_type"] == "public"
    assert "client_secret" not in provider


def test_migrate_clients_dry_run_writes_nothing() -> None:
    fake = FakeAuthentikClients()
    kc_client = _confidential_app_client()
    results = _run(
        fake, [kc_client], apply=False, secrets={kc_client["id"]: "kc2ak-test-client-secret"}
    )

    assert fake.create_provider_calls == 0
    assert fake.create_application_calls == 0
    assert results[0].outcome == CREATED
    assert results[0].authentik_ref is None


def test_migrate_clients_failed_provider_create_does_not_abort_run() -> None:
    fake = FakeAuthentikClients()

    def failing_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v3/flows/instances/":
            return fake.handler(request)
        if request.url.path == "/api/v3/propertymappings/provider/scope/":
            return fake.handler(request)
        if request.url.path == "/api/v3/providers/oauth2/" and request.method == "GET":
            return httpx.Response(200, json={"pagination": {}, "results": []})
        if request.url.path == "/api/v3/providers/oauth2/" and request.method == "POST":
            return httpx.Response(500, json={"detail": "boom"})
        raise AssertionError("unexpected request")

    ak = AuthentikClient("http://ak.example", "tok", transport=httpx.MockTransport(failing_handler))
    kc_client = _confidential_app_client()
    kc = _kc_client(clients=[kc_client], secrets={kc_client["id"]: "kc2ak-test-client-secret"})

    results = migrate_clients(
        kc,
        ak,
        "kc2ak-test",
        apply=True,
        authorization_flow=AUTH_FLOW_SLUG,
        invalidation_flow=INV_FLOW_SLUG,
    )

    assert len(results) == 1
    assert results[0].outcome == FAILED
    assert results[0].reason == API_REJECTED


# --- idempotency / matching -------------------------------------------------


def test_migrate_clients_skips_existing_matched_client() -> None:
    fake = FakeAuthentikClients()
    fake.providers[1] = {
        "pk": 1,
        "client_id": "confidential-app",
        "client_type": "confidential",
    }
    fake.applications["confidential-app"] = {"slug": "confidential-app", "provider": 1}
    kc_client = _confidential_app_client()

    results = _run(
        fake, [kc_client], apply=True, secrets={kc_client["id"]: "kc2ak-test-client-secret"}
    )

    assert results[0].outcome == SKIPPED
    assert results[0].authentik_ref == "confidential-app"
    assert fake.create_provider_calls == 0
    assert fake.create_application_calls == 0


def test_full_realm_migrates_end_to_end_and_rerun_creates_nothing() -> None:
    fake = FakeAuthentikClients()
    kc_client = _confidential_app_client()
    secrets = {kc_client["id"]: "kc2ak-test-client-secret"}

    first = _run(fake, [kc_client], apply=True, secrets=secrets)
    assert first[0].outcome == CREATED
    assert fake.create_provider_calls == 1
    assert fake.create_application_calls == 1

    second = _run(fake, [kc_client], apply=True, secrets=secrets)
    assert second[0].outcome == SKIPPED
    assert fake.create_provider_calls == 1  # unchanged -- nothing new written
    assert fake.create_application_calls == 1


# --- half-created pair repair ------------------------------------------------


def test_migrate_clients_finishes_a_half_created_pair_regardless_of_update_existing() -> None:
    # An earlier interrupted run created the provider but failed to create
    # the application. A rerun must finish the pair rather than reporting
    # SKIPPED with no application ever existing --
    # .chief/milestone-1/_goal/03-idempotency-and-matching.md's "interrupting
    # a run and re-running completes it" rule.
    fake = FakeAuthentikClients()
    fake.providers[1] = {
        "pk": 1,
        "client_id": "confidential-app",
        "client_type": "confidential",
    }
    kc_client = _confidential_app_client()

    results = _run(
        fake,
        [kc_client],
        apply=True,
        update_existing=False,  # deliberately off -- repair must not need it
        secrets={kc_client["id"]: "kc2ak-test-client-secret"},
    )

    assert results[0].outcome == CREATED
    assert fake.create_provider_calls == 0  # provider untouched, already existed
    assert fake.create_application_calls == 1
    assert fake.applications["confidential-app"]["provider"] == 1


def test_migrate_clients_half_created_pair_dry_run_plans_without_writing() -> None:
    fake = FakeAuthentikClients()
    fake.providers[1] = {"pk": 1, "client_id": "confidential-app", "client_type": "confidential"}
    kc_client = _confidential_app_client()

    results = _run(
        fake, [kc_client], apply=False, secrets={kc_client["id"]: "kc2ak-test-client-secret"}
    )

    assert results[0].outcome == CREATED
    assert results[0].authentik_ref is None
    assert fake.create_application_calls == 0


# --- --update-existing -------------------------------------------------


def test_migrate_clients_without_update_existing_never_patches() -> None:
    fake = FakeAuthentikClients()
    fake.providers[1] = {"pk": 1, "client_id": "confidential-app", "client_type": "confidential"}
    fake.applications["confidential-app"] = {"slug": "confidential-app", "provider": 1}
    kc_client = _confidential_app_client()

    results = _run(
        fake, [kc_client], apply=True, secrets={kc_client["id"]: "kc2ak-test-client-secret"}
    )

    assert results[0].outcome == SKIPPED
    assert fake.update_provider_calls == 0


def test_migrate_clients_update_existing_patches_matched_provider() -> None:
    fake = FakeAuthentikClients()
    fake.providers[1] = {"pk": 1, "client_id": "confidential-app", "client_type": "public"}
    fake.applications["confidential-app"] = {"slug": "confidential-app", "provider": 1}
    kc_client = _confidential_app_client()

    results = _run(
        fake,
        [kc_client],
        apply=True,
        update_existing=True,
        secrets={kc_client["id"]: "kc2ak-test-client-secret"},
    )

    assert results[0].outcome == UPDATED
    assert fake.update_provider_calls == 1
    assert fake.providers[1]["client_type"] == "confidential"
    assert fake.create_provider_calls == 0


def test_migrate_clients_update_existing_dry_run_plans_without_patching() -> None:
    fake = FakeAuthentikClients()
    fake.providers[1] = {"pk": 1, "client_id": "confidential-app", "client_type": "public"}
    fake.applications["confidential-app"] = {"slug": "confidential-app", "provider": 1}
    kc_client = _confidential_app_client()

    results = _run(
        fake,
        [kc_client],
        apply=False,
        update_existing=True,
        secrets={kc_client["id"]: "kc2ak-test-client-secret"},
    )

    assert results[0].outcome == UPDATED
    assert fake.update_provider_calls == 0


def test_migrate_clients_update_existing_failed_patch_does_not_abort_run() -> None:
    fake = FakeAuthentikClients()
    fake.providers[1] = {"pk": 1, "client_id": "confidential-app", "client_type": "public"}
    fake.applications["confidential-app"] = {"slug": "confidential-app", "provider": 1}

    def failing_patch(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/api/v3/providers/oauth2/") and request.method == "PATCH":
            return httpx.Response(500, json={"detail": "boom"})
        return fake.handler(request)

    ak = AuthentikClient("http://ak.example", "tok", transport=httpx.MockTransport(failing_patch))
    kc_client = _confidential_app_client()
    kc = _kc_client(clients=[kc_client], secrets={kc_client["id"]: "kc2ak-test-client-secret"})

    results = migrate_clients(
        kc,
        ak,
        "kc2ak-test",
        apply=True,
        authorization_flow=AUTH_FLOW_SLUG,
        invalidation_flow=INV_FLOW_SLUG,
        update_existing=True,
    )

    assert results[0].outcome == FAILED
    assert results[0].reason == API_REJECTED


# --- secrets never reach the report -----------------------------------------


def test_client_secret_never_appears_in_the_written_report(tmp_path: Path) -> None:
    """Client secrets pass through process memory only
    (_goal/02-safety-and-blast-radius.md). get_client_secret() registers the
    real secret for redaction the moment it is read, before migrate_clients
    ever builds a provider payload from it -- this proves the whole pipeline
    (read -> map -> write -> report) never leaks it, not just that the report
    schema happens to omit a `client_secret` field.
    """
    secret = "kc2ak-test-client-secret"
    fake = FakeAuthentikClients()
    kc_client = _confidential_app_client()

    results = _run(fake, [kc_client], apply=True, secrets={kc_client["id"]: secret})

    report = build_report(
        realm="kc2ak-test",
        applied=True,
        started_at="t0",
        finished_at="t1",
        entities=results,
        recovery_mail=compute_recovery_mail(results),
    )
    path = tmp_path / "report.json"
    write_report(path, report)
    text = path.read_text()
    assert secret not in text
    assert secret not in json.dumps(report)
