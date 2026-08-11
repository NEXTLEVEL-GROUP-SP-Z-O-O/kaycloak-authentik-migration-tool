"""migrate_groups/migrate_users/migrate_memberships against a fake Authentik
(in-memory, HTTP-shaped like the real API -- endpoints and payload shapes
confirmed live) and a Keycloak client fed from the real fixtures in
tests/fixtures/, captured from a live Keycloak 25 seeded with
deploy/keycloak/realm-kc2ak-test.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from kc2ak.authentik_client import AuthentikClient
from kc2ak.keycloak_client import KeycloakClient
from kc2ak.migrator import (
    API_REJECTED,
    CONFLICT,
    CREATED,
    EMAIL_DUPLICATE_USERNAME_NEW,
    FAILED,
    NESTED_GROUPS_UNSUPPORTED,
    SKIPPED,
    UPDATED,
    USERNAME_TAKEN_EMAIL_DIFFERS,
    migrate_groups,
    migrate_memberships,
    migrate_users,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> list[dict[str, Any]]:
    return list(json.loads((FIXTURES / name).read_text()))


def _kc_client(
    *,
    groups: list[dict[str, Any]] | None = None,
    users: list[dict[str, Any]] | None = None,
    members_by_group: dict[str, list[dict[str, Any]]] | None = None,
) -> KeycloakClient:
    groups = groups or []
    users = users or []
    members_by_group = members_by_group or {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "kc-token"})
        first = int(request.url.params.get("first", "0"))
        max_ = int(request.url.params.get("max", "100"))
        if path.endswith("/groups"):
            return httpx.Response(200, json=groups[first : first + max_])
        if path.endswith("/members"):
            group_id = path.split("/groups/")[1].split("/members")[0]
            members = members_by_group.get(group_id, [])
            return httpx.Response(200, json=members[first : first + max_])
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


class FakeAuthentik:
    """In-memory stand-in for Authentik's core users/groups endpoints,
    shaped exactly like the real responses (verified live in task-2's
    verification pass): `?username=`/`?email=`/`?name=` are exact filters,
    group records carry a `users` pk list, add_user is idempotent.
    """

    def __init__(self) -> None:
        self.groups: dict[str, dict[str, Any]] = {}
        self.users: dict[str, dict[str, Any]] = {}
        self._group_seq = 0
        self._user_seq = 100
        self.add_user_calls = 0
        self.create_user_calls = 0
        self.create_group_calls = 0
        self.update_user_calls = 0
        self.update_group_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        if path == "/api/v3/core/users/" and method == "GET":
            results = list(self.users.values())
            username = request.url.params.get("username")
            if username is not None:
                results = [u for u in results if u["username"] == username]
            email = request.url.params.get("email")
            if email is not None:
                results = [u for u in results if u["email"] == email]
            return httpx.Response(200, json={"pagination": {}, "results": results})

        if path == "/api/v3/core/users/" and method == "POST":
            self.create_user_calls += 1
            body = json.loads(request.content)
            if body["username"] in self.users:
                return httpx.Response(400, json={"username": ["This field must be unique."]})
            self._user_seq += 1
            record = {
                "pk": self._user_seq,
                "username": body["username"],
                "email": body.get("email", ""),
                "name": body.get("name", ""),
                "is_active": body.get("is_active", True),
                "attributes": body.get("attributes", {}),
            }
            self.users[body["username"]] = record
            return httpx.Response(201, json=record)

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

        if path.startswith("/api/v3/core/users/") and method == "PATCH":
            self.update_user_calls += 1
            pk = int(path.removeprefix("/api/v3/core/users/").removesuffix("/"))
            user = next((u for u in self.users.values() if u["pk"] == pk), None)
            if user is None:
                return httpx.Response(404, json={"detail": "not found"})
            body = json.loads(request.content)
            user.update(
                {
                    "email": body.get("email", user["email"]),
                    "name": body.get("name", user["name"]),
                    "is_active": body.get("is_active", user["is_active"]),
                    "attributes": body.get("attributes", user["attributes"]),
                }
            )
            return httpx.Response(200, json=user)

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


def _ak_client(fake: FakeAuthentik) -> AuthentikClient:
    return AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(fake.handler)
    )


# --- groups ------------------------------------------------------------


def test_migrate_groups_creates_flat_groups_under_apply() -> None:
    groups = _load("kc_groups.json")
    kc = _kc_client(groups=groups)
    fake = FakeAuthentik()

    results, ok_groups, group_pks, group_members = migrate_groups(
        kc, _ak_client(fake), "kc2ak-test", apply=True
    )

    by_name = {r.keycloak_ref: r for r in results}
    assert by_name["engineering"].outcome == CREATED
    assert by_name["marketing"].outcome == CREATED
    # sales has subGroupCount: 1 in the fixture -> conflict, not created.
    assert by_name["sales"].outcome == CONFLICT
    assert by_name["sales"].reason == NESTED_GROUPS_UNSUPPORTED
    assert "sales" not in group_pks
    assert "engineering" in ok_groups and "sales" not in ok_groups
    assert fake.create_group_calls == 2  # not sales


def test_migrate_groups_dry_run_writes_nothing() -> None:
    groups = _load("kc_groups.json")
    kc = _kc_client(groups=groups)
    fake = FakeAuthentik()

    results, _, group_pks, _ = migrate_groups(kc, _ak_client(fake), "kc2ak-test", apply=False)

    assert fake.create_group_calls == 0
    assert all(r.authentik_ref is None for r in results if r.kind == "group")
    assert group_pks == {}


def test_migrate_groups_skips_existing_group_and_reports_its_members() -> None:
    fake = FakeAuthentik()
    fake.groups["engineering"] = {
        "pk": "existing-pk",
        "name": "engineering",
        "attributes": {},
        "users": [7],
    }
    kc = _kc_client(groups=[{"id": "g1", "name": "engineering", "subGroups": []}])

    results, ok_groups, group_pks, group_members = migrate_groups(
        kc, _ak_client(fake), "kc2ak-test", apply=True
    )

    assert results[0].outcome == SKIPPED
    assert results[0].authentik_ref == "existing-pk"
    assert group_pks["engineering"] == "existing-pk"
    assert group_members["engineering"] == {7}
    assert fake.create_group_calls == 0


def test_migrate_groups_failed_create_does_not_abort_run() -> None:
    kc = _kc_client(
        groups=[
            {"id": "g1", "name": "engineering", "subGroups": []},
            {"id": "g2", "name": "marketing", "subGroups": []},
        ]
    )

    def failing_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v3/core/groups/" and request.method == "GET":
            return httpx.Response(200, json={"pagination": {}, "results": []})
        if request.url.path == "/api/v3/core/groups/" and request.method == "POST":
            return httpx.Response(500, json={"detail": "boom"})
        raise AssertionError("unexpected request")

    ak = AuthentikClient("http://ak.example", "tok", transport=httpx.MockTransport(failing_handler))

    results, _, group_pks, _ = migrate_groups(kc, ak, "kc2ak-test", apply=True)

    assert len(results) == 2
    assert all(r.outcome == FAILED and r.reason == API_REJECTED for r in results)
    assert group_pks == {}


# --- users ---------------------------------------------------------------


def test_migrate_users_creates_and_maps_disabled_to_inactive() -> None:
    users = _load("kc_users.json")
    kc = _kc_client(users=users)
    fake = FakeAuthentik()

    results, user_pks, resolved = migrate_users(kc, _ak_client(fake), "kc2ak-test", apply=True)

    by_username = {r.keycloak_ref: r for r in results}
    assert by_username["ajones"].outcome == CREATED
    assert fake.users["ajones"]["is_active"] is True
    assert fake.users["disableduser"]["is_active"] is False
    assert "disableduser" in user_pks


def test_migrate_users_no_email_user_creates_with_empty_email() -> None:
    users = _load("kc_users.json")
    kc = _kc_client(users=users)
    fake = FakeAuthentik()

    migrate_users(kc, _ak_client(fake), "kc2ak-test", apply=True)

    assert fake.users["noemail"]["email"] == ""


def test_migrate_users_skips_full_match_username_and_email() -> None:
    fake = FakeAuthentik()
    fake.users["ajones"] = {
        "pk": 7,
        "username": "ajones",
        "email": "alice@example.com",
        "name": "Alice Jones",
        "is_active": True,
        "attributes": {},
    }
    kc = _kc_client(
        users=[
            {
                "id": "u1",
                "username": "ajones",
                "email": "alice@example.com",
                "firstName": "Alice",
                "lastName": "Jones",
                "enabled": True,
            }
        ]
    )

    results, user_pks, resolved = migrate_users(kc, _ak_client(fake), "kc2ak-test", apply=True)

    assert results[0].outcome == SKIPPED
    assert results[0].authentik_ref == 7
    assert user_pks["ajones"] == 7
    assert fake.create_user_calls == 0


def test_migrate_users_same_username_different_email_is_conflict_and_continues() -> None:
    fake = FakeAuthentik()
    fake.users["mnowak"] = {
        "pk": 5,
        "username": "mnowak",
        "email": "old@example.com",
        "name": "M Nowak",
        "is_active": True,
        "attributes": {},
    }
    kc = _kc_client(
        users=[
            {
                "id": "u1",
                "username": "mnowak",
                "email": "new@example.com",
                "firstName": "M",
                "lastName": "Nowak",
                "enabled": True,
            },
            {
                "id": "u2",
                "username": "other",
                "email": "other@example.com",
                "firstName": "Other",
                "lastName": "User",
                "enabled": True,
            },
        ]
    )

    results, user_pks, resolved = migrate_users(kc, _ak_client(fake), "kc2ak-test", apply=True)

    conflict = next(r for r in results if r.keycloak_ref == "mnowak")
    assert conflict.outcome == CONFLICT
    assert conflict.reason == USERNAME_TAKEN_EMAIL_DIFFERS
    assert conflict.authentik_ref is None
    assert "mnowak" not in user_pks
    # the run continued: the other user still got processed.
    other = next(r for r in results if r.keycloak_ref == "other")
    assert other.outcome == CREATED


def test_migrate_users_different_username_same_email_is_created_and_flagged() -> None:
    users = _load("kc_users.json")  # euser1 and euser2 share shared@example.com
    kc = _kc_client(users=users)
    fake = FakeAuthentik()

    results, user_pks, resolved = migrate_users(kc, _ak_client(fake), "kc2ak-test", apply=True)

    by_username = {r.keycloak_ref: r for r in results}
    assert by_username["euser1"].outcome == CREATED
    assert by_username["euser1"].reason is None  # first one in, no duplicate yet
    assert by_username["euser2"].outcome == CREATED
    assert by_username["euser2"].reason == EMAIL_DUPLICATE_USERNAME_NEW
    assert "euser1" in user_pks and "euser2" in user_pks
    assert fake.users["euser1"]["email"] == fake.users["euser2"]["email"] == "shared@example.com"


def test_migrate_users_dry_run_still_flags_duplicate_email_without_writing() -> None:
    users = _load("kc_users.json")
    kc = _kc_client(users=users)
    fake = FakeAuthentik()

    results, user_pks, resolved = migrate_users(kc, _ak_client(fake), "kc2ak-test", apply=False)

    assert fake.create_user_calls == 0
    assert user_pks == {}
    by_username = {r.keycloak_ref: r for r in results}
    assert by_username["euser2"].outcome == CREATED
    assert by_username["euser2"].reason == EMAIL_DUPLICATE_USERNAME_NEW
    assert by_username["euser2"].authentik_ref is None


def test_migrate_users_failed_create_does_not_abort_run() -> None:
    kc = _kc_client(
        users=[
            {"id": "u1", "username": "a", "email": "a@example.com", "enabled": True},
            {"id": "u2", "username": "b", "email": "b@example.com", "enabled": True},
        ]
    )

    def failing_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v3/core/users/" and request.method == "GET":
            return httpx.Response(200, json={"pagination": {}, "results": []})
        if request.url.path == "/api/v3/core/users/" and request.method == "POST":
            return httpx.Response(500, json={"detail": "boom"})
        raise AssertionError("unexpected request")

    ak = AuthentikClient("http://ak.example", "tok", transport=httpx.MockTransport(failing_handler))

    results, user_pks, resolved = migrate_users(kc, ak, "kc2ak-test", apply=True)

    assert len(results) == 2
    assert all(r.outcome == FAILED and r.reason == API_REJECTED for r in results)
    assert user_pks == {}


# --- memberships -----------------------------------------------------------


def _members_setup(
    *, apply: bool
) -> tuple[FakeAuthentik, AuthentikClient, dict[str, str], dict[str, str], dict[str, set[int]]]:
    kc = _kc_client(
        groups=[{"id": "g1", "name": "engineering", "subGroups": []}],
        members_by_group={"g1": _load("kc_group_members_engineering.json")},
    )
    fake = FakeAuthentik()
    ak = _ak_client(fake)
    _, ok_groups, group_pks, group_members = migrate_groups(kc, ak, "kc2ak-test", apply=apply)
    return fake, ak, ok_groups, group_pks, group_members


def test_migrate_memberships_creates_under_apply() -> None:
    fake, ak, ok_groups, group_pks, group_members = _members_setup(apply=True)
    kc2 = _kc_client(
        groups=[{"id": "g1", "name": "engineering", "subGroups": []}],
        members_by_group={"g1": _load("kc_group_members_engineering.json")},
        users=_load("kc_users.json"),
    )
    _, user_pks, resolved_usernames = migrate_users(kc2, ak, "kc2ak-test", apply=True)

    membership_results = migrate_memberships(
        kc2,
        ak,
        "kc2ak-test",
        apply=True,
        ok_groups=ok_groups,
        group_pks=group_pks,
        group_members=group_members,
        user_pks=user_pks,
        resolved_usernames=resolved_usernames,
    )

    assert {r.outcome for r in membership_results} == {CREATED}
    assert len(membership_results) == 2  # ajones + bsmith
    ak_group_pk = group_pks["engineering"]
    assert set(fake.groups["engineering"]["users"]) == {user_pks["ajones"], user_pks["bsmith"]}
    assert all(r.authentik_ref == ak_group_pk for r in membership_results)


def test_migrate_memberships_dry_run_plans_without_writing() -> None:
    # This is the case task-2's design review caught: on a first-ever dry
    # run against an empty Authentik, users don't have real pks yet
    # (nothing was written), but their memberships must still show up in
    # the plan rather than being silently dropped.
    fake, ak, ok_groups, group_pks, group_members = _members_setup(apply=False)
    kc2 = _kc_client(
        groups=[{"id": "g1", "name": "engineering", "subGroups": []}],
        members_by_group={"g1": _load("kc_group_members_engineering.json")},
        users=_load("kc_users.json"),
    )
    _, user_pks, resolved_usernames = migrate_users(kc2, ak, "kc2ak-test", apply=False)

    assert user_pks == {}  # nothing was actually created
    assert {"ajones", "bsmith"} <= resolved_usernames

    results = migrate_memberships(
        kc2,
        ak,
        "kc2ak-test",
        apply=False,
        ok_groups=ok_groups,
        group_pks=group_pks,
        group_members=group_members,
        user_pks=user_pks,
        resolved_usernames=resolved_usernames,
    )

    assert fake.add_user_calls == 0
    assert {r.outcome for r in results} == {CREATED}
    assert len(results) == 2  # ajones + bsmith, still planned
    assert all(r.authentik_ref is None for r in results)


def test_migrate_memberships_excludes_members_whose_user_did_not_resolve() -> None:
    kc = _kc_client(
        groups=[{"id": "g1", "name": "sales", "subGroups": []}],
        members_by_group={"g1": _load("kc_group_members_sales_admins.json")},  # disableduser
    )
    fake = FakeAuthentik()
    ak = _ak_client(fake)

    results = migrate_memberships(
        kc,
        ak,
        "kc2ak-test",
        apply=True,
        ok_groups={"sales": "g1"},
        group_pks={},
        group_members={},
        user_pks={},
        resolved_usernames=set(),  # disableduser never resolved (e.g. conflicted/failed)
    )

    assert results == []
    assert fake.add_user_calls == 0


# --- end-to-end idempotency -------------------------------------------------


def test_full_realm_migrates_end_to_end_and_rerun_creates_nothing() -> None:
    """The task-2 done condition: a realm of flat groups and users migrates
    end to end, and re-running the exact same migration creates nothing.
    """
    groups = _load("kc_groups.json")
    users = _load("kc_users.json")
    members_by_group = {
        "11111111-0000-0000-0000-000000000001": _load("kc_group_members_engineering.json"),
        "11111111-0000-0000-0000-000000000002": [],
        "11111111-0000-0000-0000-000000000003": [],  # sales itself: no direct members
    }
    fake = FakeAuthentik()
    ak = _ak_client(fake)

    def run() -> tuple[list[Any], list[Any], list[Any]]:
        kc = _kc_client(groups=groups, users=users, members_by_group=members_by_group)
        group_results, ok_groups, group_pks, group_members = migrate_groups(
            kc, ak, "kc2ak-test", apply=True
        )
        user_results, user_pks, resolved_usernames = migrate_users(kc, ak, "kc2ak-test", apply=True)
        membership_results = migrate_memberships(
            kc,
            ak,
            "kc2ak-test",
            apply=True,
            ok_groups=ok_groups,
            group_pks=group_pks,
            group_members=group_members,
            user_pks=user_pks,
            resolved_usernames=resolved_usernames,
        )
        return group_results, user_results, membership_results

    first_groups, first_users, first_memberships = run()
    assert sum(1 for r in first_groups if r.outcome == CREATED) == 2  # engineering, marketing
    assert sum(1 for r in first_groups if r.outcome == CONFLICT) == 1  # sales, nested
    assert sum(1 for r in first_users if r.outcome == CREATED) == 7
    assert len(first_memberships) == 2  # ajones + bsmith in engineering

    first_create_group_calls = fake.create_group_calls
    first_create_user_calls = fake.create_user_calls
    first_add_user_calls = fake.add_user_calls

    second_groups, second_users, second_memberships = run()

    # nothing new was written on the second pass.
    assert fake.create_group_calls == first_create_group_calls
    assert fake.create_user_calls == first_create_user_calls
    assert fake.add_user_calls == first_add_user_calls

    assert all(r.outcome in (SKIPPED, CONFLICT) for r in second_groups)
    assert all(r.outcome == SKIPPED for r in second_users)
    assert all(r.outcome == SKIPPED for r in second_memberships)


# --- --update-existing -----------------------------------------------------


def test_migrate_groups_without_update_existing_never_patches() -> None:
    """Safety rule (_goal/02-safety-and-blast-radius.md): without the flag,
    a matched object is only ever skipped, never modified.
    """
    fake = FakeAuthentik()
    fake.groups["engineering"] = {
        "pk": "existing-pk",
        "name": "engineering",
        "attributes": {},
        "users": [],
    }
    kc = _kc_client(groups=[{"id": "g1", "name": "engineering", "subGroups": []}])

    results, _, _, _ = migrate_groups(kc, _ak_client(fake), "kc2ak-test", apply=True)

    assert results[0].outcome == SKIPPED
    assert fake.update_group_calls == 0


def test_migrate_groups_update_existing_patches_matched_group() -> None:
    fake = FakeAuthentik()
    fake.groups["engineering"] = {
        "pk": "existing-pk",
        "name": "engineering",
        "attributes": {},
        "users": [],
    }
    kc = _kc_client(groups=[{"id": "g1", "name": "engineering", "subGroups": []}])

    results, _, group_pks, _ = migrate_groups(
        kc, _ak_client(fake), "kc2ak-test", apply=True, update_existing=True
    )

    assert results[0].outcome == UPDATED
    assert results[0].authentik_ref == "existing-pk"
    assert group_pks["engineering"] == "existing-pk"
    assert fake.update_group_calls == 1
    assert fake.create_group_calls == 0


def test_migrate_groups_update_existing_dry_run_plans_without_patching() -> None:
    fake = FakeAuthentik()
    fake.groups["engineering"] = {
        "pk": "existing-pk",
        "name": "engineering",
        "attributes": {},
        "users": [],
    }
    kc = _kc_client(groups=[{"id": "g1", "name": "engineering", "subGroups": []}])

    results, _, _, _ = migrate_groups(
        kc, _ak_client(fake), "kc2ak-test", apply=False, update_existing=True
    )

    assert results[0].outcome == UPDATED
    assert fake.update_group_calls == 0


def test_migrate_users_without_update_existing_never_patches() -> None:
    fake = FakeAuthentik()
    fake.users["ajones"] = {
        "pk": 7,
        "username": "ajones",
        "email": "alice@example.com",
        "name": "Alice Jones",
        "is_active": True,
        "attributes": {},
    }
    kc = _kc_client(
        users=[
            {
                "id": "u1",
                "username": "ajones",
                "email": "alice@example.com",
                "firstName": "Alice",
                "lastName": "Jones",
                "enabled": True,
            }
        ]
    )

    results, _, _ = migrate_users(kc, _ak_client(fake), "kc2ak-test", apply=True)

    assert results[0].outcome == SKIPPED
    assert fake.update_user_calls == 0


def test_migrate_users_update_existing_patches_matched_user() -> None:
    fake = FakeAuthentik()
    fake.users["ajones"] = {
        "pk": 7,
        "username": "ajones",
        "email": "alice@example.com",
        "name": "Alice Jones",
        "is_active": True,
        "attributes": {},
    }
    kc = _kc_client(
        users=[
            {
                "id": "u1",
                "username": "ajones",
                "email": "alice@example.com",
                "firstName": "Alice",
                "lastName": "Jonesova",
                "enabled": True,
            }
        ]
    )

    results, user_pks, _ = migrate_users(
        kc, _ak_client(fake), "kc2ak-test", apply=True, update_existing=True
    )

    assert results[0].outcome == UPDATED
    assert results[0].authentik_ref == 7
    assert user_pks["ajones"] == 7
    assert fake.update_user_calls == 1
    assert fake.create_user_calls == 0
    assert fake.users["ajones"]["name"] == "Alice Jonesova"


def test_migrate_users_update_existing_leaves_conflict_untouched() -> None:
    """CONFLICT is a partial/ambiguous match, not a match -- update_existing
    must not turn a username-taken-different-email conflict into a write.
    """
    fake = FakeAuthentik()
    fake.users["ajones"] = {
        "pk": 7,
        "username": "ajones",
        "email": "someone-else@example.com",
        "name": "Alice Jones",
        "is_active": True,
        "attributes": {},
    }
    kc = _kc_client(
        users=[
            {
                "id": "u1",
                "username": "ajones",
                "email": "alice@example.com",
                "firstName": "Alice",
                "lastName": "Jones",
                "enabled": True,
            }
        ]
    )

    results, _, _ = migrate_users(
        kc, _ak_client(fake), "kc2ak-test", apply=True, update_existing=True
    )

    assert results[0].outcome == CONFLICT
    assert results[0].reason == USERNAME_TAKEN_EMAIL_DIFFERS
    assert fake.update_user_calls == 0
    assert fake.create_user_calls == 0
