"""migrate_roles/migrate_role_assignments against a fake Authentik (in-memory,
HTTP-shaped like the real API) and a Keycloak client fed from the real
fixtures in tests/fixtures/, captured from a live Keycloak 25 seeded with
deploy/keycloak/realm-kc2ak-test.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from kc2ak.authentik_client import AuthentikClient
from kc2ak.keycloak_client import KeycloakClient
from kc2ak.mappers.roles import COMPOSITE_ROLE_UNSUPPORTED, ROLE_NAME_TAKEN_BY_GROUP
from kc2ak.migrator import (
    API_REJECTED,
    CONFLICT,
    CREATED,
    FAILED,
    ROLE_ASSIGNMENT_ROLE_MISSING,
    SKIPPED,
    UPDATED,
    migrate_role_assignments,
    migrate_roles,
)

FIXTURES = Path(__file__).parent / "fixtures"
REALM = "kc2ak-test"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def _roles_fixture() -> list[dict[str, Any]]:
    return list(_load("kc_roles.json"))


def _user_roles_fixture(username: str) -> list[dict[str, Any]]:
    return list(_load(f"kc_user_role_mappings_{username}.json"))


def _kc_client(
    *,
    roles: list[dict[str, Any]] | None = None,
    users: list[dict[str, Any]] | None = None,
    user_roles_by_id: dict[str, list[dict[str, Any]]] | None = None,
) -> KeycloakClient:
    roles = roles or []
    users = users or []
    user_roles_by_id = user_roles_by_id or {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "kc-token"})
        first = int(request.url.params.get("first", "0"))
        max_ = int(request.url.params.get("max", "100"))
        if path.endswith("/role-mappings/realm"):
            user_id = path.split("/users/")[1].split("/role-mappings/")[0]
            return httpx.Response(200, json=user_roles_by_id.get(user_id, []))
        if path.endswith("/roles"):
            return httpx.Response(200, json=roles[first : first + max_])
        if path.endswith("/users"):
            return httpx.Response(200, json=users[first : first + max_])
        raise AssertionError(f"unexpected Keycloak request: {path}")

    client = KeycloakClient(
        "http://kc.example",
        realm_admin="admin",
        admin_password="admin-pw",
        transport=httpx.MockTransport(handler),
    )
    client.authenticate()
    return client


class FakeAuthentikGroups:
    """In-memory stand-in for the group subset of Authentik's API --
    same shapes as test_migrator.py's FakeAuthentik, confirmed live.
    """

    def __init__(self) -> None:
        self.groups: dict[str, dict[str, Any]] = {}
        self._group_seq = 0
        self.add_user_calls = 0
        self.create_group_calls = 0
        self.update_group_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        if path == "/api/v3/core/groups/" and method == "GET":
            results = list(self.groups.values())
            name = request.url.params.get("name")
            if name is not None:
                results = [g for g in results if g["name"] == name]
            return httpx.Response(200, json={"pagination": {}, "results": results})

        if path == "/api/v3/core/groups/" and method == "POST":
            self.create_group_calls += 1
            body = json.loads(request.content)
            self._group_seq += 1
            record = {
                "pk": f"grp-{self._group_seq}",
                "name": body["name"],
                "attributes": body.get("attributes", {}),
                "users": [],
            }
            self.groups[body["name"]] = record
            return httpx.Response(201, json=record)

        if (
            path.startswith("/api/v3/core/groups/")
            and method == "PATCH"
            and not path.endswith("/add_user/")
        ):
            self.update_group_calls += 1
            pk = path.removeprefix("/api/v3/core/groups/").removesuffix("/")
            group = next((g for g in self.groups.values() if g["pk"] == pk), None)
            if group is None:
                return httpx.Response(404, json={"detail": "not found"})
            body = json.loads(request.content)
            group.update({"attributes": body.get("attributes", group["attributes"])})
            return httpx.Response(200, json=group)

        if path.endswith("/add_user/") and method == "POST":
            self.add_user_calls += 1
            group_pk = path.removeprefix("/api/v3/core/groups/").removesuffix("/add_user/")
            group = next((g for g in self.groups.values() if g["pk"] == group_pk), None)
            if group is None:
                return httpx.Response(404, json={"detail": "not found"})
            user_pk = json.loads(request.content)["pk"]
            if user_pk not in group["users"]:
                group["users"].append(user_pk)
            return httpx.Response(204)

        raise AssertionError(f"unexpected Authentik request: {method} {path}")


def _ak_client(fake: FakeAuthentikGroups) -> AuthentikClient:
    return AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(fake.handler)
    )


# --- migrate_roles -----------------------------------------------------------


def test_migrate_roles_excludes_builtins_before_the_read_is_counted() -> None:
    fake = FakeAuthentikGroups()
    # engineering already exists as a plain (non-role-origin) group -- as it
    # would after migrate_groups ran first in the fixed processing order.
    fake.groups["engineering"] = {
        "pk": "existing-pk",
        "name": "engineering",
        "attributes": {},
        "users": [],
    }
    kc = _kc_client(roles=_roles_fixture())

    results, role_pks, role_conflicted, role_members = migrate_roles(
        kc, _ak_client(fake), REALM, apply=True
    )

    by_name = {r.keycloak_ref: r for r in results}
    # default-roles-kc2ak-test, offline_access, uma_authorization never
    # become entities at all.
    assert set(by_name) == {"code-reviewer", "employee", "engineering", "senior-engineer"}

    assert by_name["code-reviewer"].outcome == CREATED
    assert by_name["employee"].outcome == CREATED
    assert by_name["engineering"].outcome == CONFLICT
    assert by_name["engineering"].reason == ROLE_NAME_TAKEN_BY_GROUP
    assert by_name["senior-engineer"].outcome == CONFLICT
    assert by_name["senior-engineer"].reason == COMPOSITE_ROLE_UNSUPPORTED

    assert role_conflicted == {"engineering", "senior-engineer"}
    assert set(role_pks) == {"code-reviewer", "employee"}
    assert fake.create_group_calls == 2  # engineering/senior-engineer wrote nothing


def test_migrate_roles_dry_run_writes_nothing() -> None:
    kc = _kc_client(roles=_roles_fixture())
    fake = FakeAuthentikGroups()

    results, role_pks, _role_conflicted, _role_members = migrate_roles(
        kc, _ak_client(fake), REALM, apply=False
    )

    assert fake.create_group_calls == 0
    assert role_pks == {}
    by_name = {r.keycloak_ref: r for r in results}
    assert by_name["employee"].outcome == CREATED
    assert by_name["employee"].authentik_ref is None


def test_map_role_stamps_kc2ak_origin_and_a_rerun_reads_it_back_as_skipped() -> None:
    # The re-run round trip that makes a migrated role distinguishable from
    # a pre-existing group of the same name --
    # .chief/milestone-2/_contract/01-role-mapping.md.
    kc = _kc_client(roles=[{"id": "r1", "name": "employee", "composite": False}])
    fake = FakeAuthentikGroups()
    ak = _ak_client(fake)

    first, _, _, _ = migrate_roles(kc, ak, REALM, apply=True)
    assert first[0].outcome == CREATED
    assert fake.groups["employee"]["attributes"]["kc2ak_origin"] == "realm_role"

    kc2 = _kc_client(roles=[{"id": "r1", "name": "employee", "composite": False}])
    second, role_pks, role_conflicted, _ = migrate_roles(kc2, ak, REALM, apply=True)

    assert second[0].outcome == SKIPPED
    assert role_conflicted == set()
    assert role_pks["employee"] == fake.groups["employee"]["pk"]
    assert fake.create_group_calls == 1  # nothing new on the second pass


def test_migrate_roles_failed_create_does_not_abort_run() -> None:
    kc = _kc_client(
        roles=[
            {"id": "r1", "name": "employee", "composite": False},
            {"id": "r2", "name": "manager", "composite": False},
        ]
    )

    def failing_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v3/core/groups/" and request.method == "GET":
            return httpx.Response(200, json={"pagination": {}, "results": []})
        if request.url.path == "/api/v3/core/groups/" and request.method == "POST":
            return httpx.Response(500, json={"detail": "boom"})
        raise AssertionError("unexpected request")

    ak = AuthentikClient("http://ak.example", "tok", transport=httpx.MockTransport(failing_handler))

    results, role_pks, role_conflicted, _ = migrate_roles(kc, ak, REALM, apply=True)

    assert len(results) == 2
    assert all(r.outcome == FAILED and r.reason == API_REJECTED for r in results)
    assert role_pks == {}
    assert role_conflicted == set()  # FAILED is not CONFLICT


def test_migrate_roles_update_existing_patches_matched_role_origin_group() -> None:
    fake = FakeAuthentikGroups()
    fake.groups["employee"] = {
        "pk": "existing-pk",
        "name": "employee",
        "attributes": {"kc2ak_origin": "realm_role", "keycloak_id": "r1"},
        "users": [],
    }
    kc = _kc_client(
        roles=[{"id": "r1", "name": "employee", "composite": False, "description": "updated desc"}]
    )

    results, role_pks, _role_conflicted, _role_members = migrate_roles(
        kc, _ak_client(fake), REALM, apply=True, update_existing=True
    )

    assert results[0].outcome == UPDATED
    assert results[0].authentik_ref == "existing-pk"
    assert role_pks["employee"] == "existing-pk"
    assert fake.update_group_calls == 1
    assert fake.create_group_calls == 0


def test_role_field_description_reported_as_unmapped() -> None:
    kc = _kc_client(roles=_roles_fixture())
    fake = FakeAuthentikGroups()

    results, _, _, _ = migrate_roles(kc, _ak_client(fake), REALM, apply=True)

    by_name = {r.keycloak_ref: r for r in results}
    assert {"type": "role_field", "name": "description", "why": "not carried over"} in by_name[
        "employee"
    ].unmapped


# --- migrate_role_assignments -------------------------------------------------


def _run_role_pipeline(
    *, apply: bool
) -> tuple[FakeAuthentikGroups, AuthentikClient, dict[str, str], set[str], dict[str, set[int]]]:
    kc = _kc_client(roles=_roles_fixture())
    fake = FakeAuthentikGroups()
    # As in the real seed, "engineering" is both a Keycloak group (created by
    # an earlier migrate_groups pass, per the fixed processing order) and a
    # realm role of the same name -- the collision migrate_roles must CONFLICT.
    fake.groups["engineering"] = {
        "pk": "existing-pk",
        "name": "engineering",
        "attributes": {},
        "users": [],
    }
    ak = _ak_client(fake)
    _, role_pks, role_conflicted, role_members = migrate_roles(kc, ak, REALM, apply=apply)
    return fake, ak, role_pks, role_conflicted, role_members


def _users_and_role_mappings() -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    users = list(_load("kc_users.json"))
    by_username = {u["username"]: u["id"] for u in users}
    user_roles_by_id = {
        by_username["ajones"]: _user_roles_fixture("ajones"),
        by_username["bsmith"]: _user_roles_fixture("bsmith"),
        by_username["cbaker"]: _user_roles_fixture("cbaker"),
        by_username["noemail"]: _user_roles_fixture("noemail"),
    }
    return users, user_roles_by_id


def test_migrate_role_assignments_creates_membership_for_a_plain_role_holder() -> None:
    fake, ak, role_pks, role_conflicted, role_members = _run_role_pipeline(apply=True)
    users, user_roles_by_id = _users_and_role_mappings()
    kc2 = _kc_client(users=users, user_roles_by_id=user_roles_by_id)

    # bsmith already has an Authentik pk in this scenario (simulating that
    # migrate_users ran first, per the fixed processing order).
    user_pks = {"ajones": 201, "bsmith": 202, "cbaker": 203, "noemail": 204}
    resolved_usernames = {"ajones", "bsmith", "cbaker", "noemail"}

    results = migrate_role_assignments(
        kc2,
        ak,
        REALM,
        apply=True,
        role_pks=role_pks,
        role_conflicted=role_conflicted,
        role_members=role_members,
        user_pks=user_pks,
        resolved_usernames=resolved_usernames,
    )

    by_ref = {r.keycloak_ref: r for r in results}
    assert by_ref["bsmith/employee"].outcome == CREATED
    assert by_ref["bsmith/employee"].authentik_ref == role_pks["employee"]
    assert 202 in fake.groups["employee"]["users"]


def test_migrate_role_assignments_composite_holder_gets_role_assignment_role_missing() -> None:
    fake, ak, role_pks, role_conflicted, role_members = _run_role_pipeline(apply=True)
    users, user_roles_by_id = _users_and_role_mappings()
    kc2 = _kc_client(users=users, user_roles_by_id=user_roles_by_id)

    user_pks = {"ajones": 201, "bsmith": 202, "cbaker": 203, "noemail": 204}
    resolved_usernames = {"ajones", "bsmith", "cbaker", "noemail"}

    results = migrate_role_assignments(
        kc2,
        ak,
        REALM,
        apply=True,
        role_pks=role_pks,
        role_conflicted=role_conflicted,
        role_members=role_members,
        user_pks=user_pks,
        resolved_usernames=resolved_usernames,
    )

    by_ref = {r.keycloak_ref: r for r in results}
    # ajones is assigned only the composite senior-engineer -- CONFLICT, and
    # this names *who* lost access rather than being silently dropped.
    assert by_ref["ajones/senior-engineer"].outcome == CONFLICT
    assert by_ref["ajones/senior-engineer"].reason == ROLE_ASSIGNMENT_ROLE_MISSING
    assert by_ref["ajones/senior-engineer"].authentik_ref is None
    # cbaker is assigned the name-collision role "engineering" -- also CONFLICT.
    assert by_ref["cbaker/engineering"].outcome == CONFLICT
    assert by_ref["cbaker/engineering"].reason == ROLE_ASSIGNMENT_ROLE_MISSING


def test_migrate_role_assignments_builtin_role_produces_no_entity() -> None:
    # noemail's seeded offline_access assignment must not become a
    # membership entity at all -- built-ins are excluded before the read is
    # counted, same as at the realm level.
    fake, ak, role_pks, role_conflicted, role_members = _run_role_pipeline(apply=True)
    users, user_roles_by_id = _users_and_role_mappings()
    kc2 = _kc_client(users=users, user_roles_by_id=user_roles_by_id)

    results = migrate_role_assignments(
        kc2,
        ak,
        REALM,
        apply=True,
        role_pks=role_pks,
        role_conflicted=role_conflicted,
        role_members=role_members,
        user_pks={"noemail": 204},
        resolved_usernames={"noemail"},
    )

    assert results == []
    assert fake.add_user_calls == 0


def test_migrate_role_assignments_dry_run_plans_without_writing() -> None:
    fake, ak, role_pks, role_conflicted, role_members = _run_role_pipeline(apply=False)
    users, user_roles_by_id = _users_and_role_mappings()
    kc2 = _kc_client(users=users, user_roles_by_id=user_roles_by_id)

    results = migrate_role_assignments(
        kc2,
        ak,
        REALM,
        apply=False,
        role_pks=role_pks,
        role_conflicted=role_conflicted,
        role_members=role_members,
        user_pks={},
        resolved_usernames={"ajones", "bsmith", "cbaker", "noemail"},
    )

    assert fake.add_user_calls == 0
    by_ref = {r.keycloak_ref: r for r in results}
    assert by_ref["bsmith/employee"].outcome == CREATED
    assert by_ref["bsmith/employee"].authentik_ref is None
    assert by_ref["ajones/senior-engineer"].outcome == CONFLICT


def test_migrate_role_assignments_excludes_users_who_did_not_resolve() -> None:
    fake, ak, role_pks, role_conflicted, role_members = _run_role_pipeline(apply=True)
    users, user_roles_by_id = _users_and_role_mappings()
    kc2 = _kc_client(users=users, user_roles_by_id=user_roles_by_id)

    results = migrate_role_assignments(
        kc2,
        ak,
        REALM,
        apply=True,
        role_pks=role_pks,
        role_conflicted=role_conflicted,
        role_members=role_members,
        user_pks={},
        resolved_usernames=set(),  # nobody resolved (e.g. all conflicted upstream)
    )

    assert results == []
    assert fake.add_user_calls == 0


def test_full_role_pipeline_end_to_end_and_rerun_creates_nothing() -> None:
    """The task-2 done condition: a realm's roles and role assignments
    migrate end to end, and re-running creates nothing.
    """
    fake = FakeAuthentikGroups()
    # As in the real seed: "engineering" is both a pre-existing Keycloak
    # group and a colliding realm role name.
    fake.groups["engineering"] = {
        "pk": "existing-pk",
        "name": "engineering",
        "attributes": {},
        "users": [],
    }
    ak = _ak_client(fake)
    users, user_roles_by_id = _users_and_role_mappings()
    user_pks = {"ajones": 201, "bsmith": 202, "cbaker": 203, "noemail": 204}
    resolved_usernames = {"ajones", "bsmith", "cbaker", "noemail"}

    def run() -> tuple[list[Any], list[Any]]:
        kc_roles = _kc_client(roles=_roles_fixture())
        role_results, role_pks, role_conflicted, role_members = migrate_roles(
            kc_roles, ak, REALM, apply=True
        )
        kc_assignments = _kc_client(users=users, user_roles_by_id=user_roles_by_id)
        assignment_results = migrate_role_assignments(
            kc_assignments,
            ak,
            REALM,
            apply=True,
            role_pks=role_pks,
            role_conflicted=role_conflicted,
            role_members=role_members,
            user_pks=user_pks,
            resolved_usernames=resolved_usernames,
        )
        return role_results, assignment_results

    first_roles, first_assignments = run()
    assert sum(1 for r in first_roles if r.outcome == CREATED) == 2  # employee, code-reviewer
    assert sum(1 for r in first_roles if r.outcome == CONFLICT) == 2  # engineering, senior-engineer
    assert sum(1 for r in first_assignments if r.outcome == CREATED) == 1  # bsmith/employee
    assert sum(1 for r in first_assignments if r.outcome == CONFLICT) == 2

    first_create_group_calls = fake.create_group_calls
    first_add_user_calls = fake.add_user_calls

    second_roles, second_assignments = run()

    assert fake.create_group_calls == first_create_group_calls
    assert fake.add_user_calls == first_add_user_calls
    assert all(r.outcome in (SKIPPED, CONFLICT) for r in second_roles)
    assert all(r.outcome in (SKIPPED, CONFLICT) for r in second_assignments)
