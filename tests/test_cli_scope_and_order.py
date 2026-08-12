"""End-to-end --only scope, processing-order, and counts-reconciliation
behaviour through the CLI
(.chief/milestone-2/_contract/03-cli-and-report-extensions.md,
.chief/milestone-2/_goal/03-continuity-with-milestone-1.md). KeycloakClient/
AuthentikClient are monkeypatched to real instances backed by
httpx.MockTransport, following the same pattern as test_cli_recovery_mail.py,
so the whole migrate() path -- preconditions, every migrate_* function, the
report -- runs for real against fakes shaped like the live APIs.

"federated-links" has no migrator yet (task-5): it is exercised here only as
CLI surface (parsed, ordered, printed, zero writes). "idps" now has a real
migrator (task-4); this file's fake Keycloak has no seeded identity
providers, so it still exercises the same "in scope, writes nothing" shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from kc2ak import redact as redact_mod
from kc2ak.authentik_client import AuthentikClient
from kc2ak.cli import app
from kc2ak.keycloak_client import KeycloakClient

runner = CliRunner()

REALM = "x"
AUTH_FLOW_SLUG = "auth-flow"
INV_FLOW_SLUG = "inv-flow"
AUTH_FLOW_PK = "11111111-aaaa-0000-0000-000000000001"
INV_FLOW_PK = "22222222-bbbb-0000-0000-000000000002"

KC_GROUPS = [{"id": "g1", "name": "engineering", "subGroupCount": 0}]
KC_ROLES = [{"id": "r1", "name": "custom-role", "composite": False}]
KC_USERS = [
    {
        "id": "u1",
        "username": "alice",
        "email": "alice@example.com",
        "firstName": "A",
        "lastName": "L",
        "enabled": True,
    },
    {
        "id": "u2",
        "username": "bob",
        "email": "bob@example.com",
        "firstName": "B",
        "lastName": "O",
        "enabled": True,
    },
]
GROUP_MEMBERS = {"g1": [{"id": "u1", "username": "alice"}]}
USER_ROLES = {"u1": [{"name": "custom-role"}], "u2": []}


def setup_function() -> None:
    redact_mod._secrets.clear()


def _kc_handler(
    *,
    groups: list[dict[str, Any]],
    roles: list[dict[str, Any]],
    users: list[dict[str, Any]],
    group_members: dict[str, list[dict[str, Any]]],
    user_roles: dict[str, list[dict[str, Any]]],
    clients: list[dict[str, Any]],
    requests: list[tuple[str, str]],
):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "kc-token"})
        requests.append((request.method, path))
        first = int(request.url.params.get("first", "0"))
        max_ = int(request.url.params.get("max", "100"))
        if path.endswith("/groups"):
            return httpx.Response(200, json=groups[first : first + max_])
        if "/groups/" in path and path.endswith("/members"):
            gid = path.split("/groups/")[1].split("/members")[0]
            return httpx.Response(200, json=group_members.get(gid, [])[first : first + max_])
        if path.endswith("/roles"):
            return httpx.Response(200, json=roles[first : first + max_])
        if path.endswith("/users"):
            return httpx.Response(200, json=users[first : first + max_])
        if path.endswith("/role-mappings/realm"):
            uid = path.split("/users/")[1].split("/role-mappings/realm")[0]
            return httpx.Response(200, json=user_roles.get(uid, []))
        if path.endswith("/clients"):
            return httpx.Response(200, json=clients[first : first + max_])
        if path.endswith("/identity-provider/instances"):
            return httpx.Response(200, json=[])
        raise AssertionError(f"unexpected Keycloak request: {path}")

    return handler


class FakeAuthentik:
    """In-memory stand-in for the subset of Authentik's API this milestone's
    migrators touch: groups (shared by both plain groups and realm roles),
    users, group membership, and (only when clients are in scope) flows,
    providers, applications.
    """

    def __init__(self) -> None:
        self.flows = {AUTH_FLOW_SLUG: AUTH_FLOW_PK, INV_FLOW_SLUG: INV_FLOW_PK}
        self.groups: dict[str, dict[str, Any]] = {}
        self.users: dict[str, dict[str, Any]] = {}
        self.providers: dict[int, dict[str, Any]] = {}
        self.applications: dict[str, dict[str, Any]] = {}
        self._group_seq = 0
        self._user_seq = 0
        self._provider_seq = 0
        self.create_group_calls = 0
        self.create_user_calls = 0
        self.create_provider_calls = 0
        self.create_application_calls = 0
        self.add_user_calls: list[tuple[str, int]] = []
        self.requests: list[tuple[str, str]] = []

    def seed_group(
        self, name: str, *, role_origin: bool = False, members: list[int] | None = None
    ) -> str:
        self._group_seq += 1
        pk = f"grp-{self._group_seq}"
        attributes = {"kc2ak_origin": "realm_role"} if role_origin else {}
        self.groups[name] = {
            "pk": pk,
            "name": name,
            "attributes": attributes,
            "users": members or [],
        }
        return pk

    def seed_user(self, username: str, *, email: str = "", is_active: bool = True) -> int:
        self._user_seq += 1
        pk = self._user_seq
        self.users[username] = {
            "pk": pk,
            "username": username,
            "email": email,
            "is_active": is_active,
        }
        return pk

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        if path == "/api/v3/core/users/me/" and method == "GET":
            return httpx.Response(200, json={"user": {"username": "akadmin"}})

        self.requests.append((method, path))

        if path == "/api/v3/flows/instances/" and method == "GET":
            slug = request.url.params.get("slug")
            pk = self.flows.get(slug or "")
            results = [{"pk": pk, "slug": slug}] if pk else []
            return httpx.Response(200, json={"pagination": {}, "results": results})

        if path == "/api/v3/core/groups/" and method == "GET":
            name = request.url.params.get("name")
            existing = self.groups.get(name or "")
            results = [existing] if existing else []
            return httpx.Response(200, json={"pagination": {}, "results": results})

        if path == "/api/v3/core/groups/" and method == "POST":
            self.create_group_calls += 1
            body = json.loads(request.content)
            self._group_seq += 1
            pk = f"grp-{self._group_seq}"
            record = {"pk": pk, "users": [], **body}
            self.groups[body["name"]] = record
            return httpx.Response(201, json=record)

        if path.endswith("/add_user/") and method == "POST":
            pk = path.removeprefix("/api/v3/core/groups/").removesuffix("/add_user/")
            body = json.loads(request.content)
            self.add_user_calls.append((pk, body["pk"]))
            return httpx.Response(204)

        if path == "/api/v3/core/users/" and method == "GET":
            username = request.url.params.get("username")
            email = request.url.params.get("email")
            results = list(self.users.values())
            if username is not None:
                results = [u for u in results if u["username"] == username]
            if email is not None:
                results = [u for u in results if u["email"] == email]
            return httpx.Response(200, json={"results": results})

        if path == "/api/v3/core/users/" and method == "POST":
            self.create_user_calls += 1
            body = json.loads(request.content)
            self._user_seq += 1
            record = {
                "pk": self._user_seq,
                "username": body["username"],
                "email": body.get("email", ""),
                "is_active": body.get("is_active", True),
            }
            self.users[body["username"]] = record
            return httpx.Response(201, json=record)

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

        if path == "/api/v3/core/applications/" and method == "GET":
            slug = request.url.params.get("slug")
            results = [a for a in self.applications.values() if a["slug"] == slug]
            return httpx.Response(200, json={"pagination": {}, "results": results})

        if path == "/api/v3/core/applications/" and method == "POST":
            self.create_application_calls += 1
            body = json.loads(request.content)
            self.applications[body["slug"]] = {**body}
            return httpx.Response(201, json={**body})

        raise AssertionError(f"unexpected Authentik request: {method} {path}")


def _patch_clients(
    monkeypatch: pytest.MonkeyPatch,
    *,
    ak: FakeAuthentik,
    kc_requests: list[tuple[str, str]],
    kc_groups: list[dict[str, Any]] | None = None,
    kc_roles: list[dict[str, Any]] | None = None,
    kc_users: list[dict[str, Any]] | None = None,
    kc_group_members: dict[str, list[dict[str, Any]]] | None = None,
    kc_user_roles: dict[str, list[dict[str, Any]]] | None = None,
    kc_clients: list[dict[str, Any]] | None = None,
) -> None:
    kc_handler = _kc_handler(
        groups=kc_groups if kc_groups is not None else KC_GROUPS,
        roles=kc_roles if kc_roles is not None else KC_ROLES,
        users=kc_users if kc_users is not None else KC_USERS,
        group_members=kc_group_members if kc_group_members is not None else GROUP_MEMBERS,
        user_roles=kc_user_roles if kc_user_roles is not None else USER_ROLES,
        clients=kc_clients if kc_clients is not None else [],
        requests=kc_requests,
    )

    def kc_factory(base_url: str, **kwargs: Any) -> KeycloakClient:
        kwargs.pop("transport", None)
        return KeycloakClient(base_url, transport=httpx.MockTransport(kc_handler), **kwargs)

    def ak_factory(base_url: str, token: str, **kwargs: Any) -> AuthentikClient:
        kwargs.pop("transport", None)
        return AuthentikClient(base_url, token, transport=httpx.MockTransport(ak.handler), **kwargs)

    monkeypatch.setattr("kc2ak.cli.KeycloakClient", kc_factory)
    monkeypatch.setattr("kc2ak.cli.AuthentikClient", ak_factory)


def _set_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KC_URL", "http://kc.example")
    monkeypatch.setenv("KC_REALM_ADMIN", "admin")
    monkeypatch.setenv("KC_ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("AK_URL", "http://ak.example")
    monkeypatch.setenv("AK_TOKEN", "ak-token")


def _run(*args: str, report_path: Path) -> Any:
    return runner.invoke(
        app,
        ["migrate", "--realm", REALM, "--report", str(report_path), *args],
    )


# --- "--only" with each of the seven values: nothing outside the selection
# is written -- the property most likely to regress
# (.chief/milestone-2/_contract/03-cli-and-report-extensions.md's "Each is
# independently selectable ... never implicitly writes another kind").


def test_only_idps_writes_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    result = _run("--apply", "--only", "idps", report_path=tmp_path / "r.json")
    assert result.exit_code == 0, result.output
    assert ak.create_group_calls == 0
    assert ak.create_user_calls == 0
    assert ak.add_user_calls == []
    assert "idps" in result.output


def test_only_federated_links_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    result = _run("--apply", "--only", "federated-links", report_path=tmp_path / "r.json")
    assert result.exit_code == 0, result.output
    assert ak.create_group_calls == 0
    assert ak.create_user_calls == 0
    assert ak.add_user_calls == []
    assert "links" in result.output


def test_only_groups_creates_only_the_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    result = _run("--apply", "--only", "groups", report_path=tmp_path / "r.json")
    assert result.exit_code == 0, result.output
    assert ak.create_group_calls == 1
    assert "kc2ak_origin" not in ak.groups["engineering"]["attributes"]
    assert ak.create_user_calls == 0
    assert ak.add_user_calls == []


def test_only_roles_creates_only_the_role_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    result = _run("--apply", "--only", "roles", report_path=tmp_path / "r.json")
    # alice's role assignment FAILs -- she has no pre-existing Authentik
    # account and "users" is not in scope, so the users pass stayed a dry,
    # read-only match (same semantics as m1's "--only memberships" against a
    # fresh instance). A FAILED entity gates exit 1; the point of this test
    # is that "roles" alone still wrote *only* the role, nothing extra.
    assert result.exit_code == 1, result.output
    assert ak.create_group_calls == 1
    assert ak.groups["custom-role"]["attributes"]["kc2ak_origin"] == "realm_role"
    assert ak.create_user_calls == 0
    assert ak.add_user_calls == []


def test_only_users_creates_only_users(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    result = _run("--apply", "--only", "users", report_path=tmp_path / "r.json")
    assert result.exit_code == 0, result.output
    assert ak.create_user_calls == 2
    assert ak.create_group_calls == 0
    assert ak.add_user_calls == []


def test_only_memberships_matches_pre_existing_and_writes_only_the_link(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """--only memberships means "match against what an earlier run already
    created" (cli.py), never "create the groups/users I explicitly scoped
    out" -- proven by seeding the group and user Authentik already has.
    """
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    group_pk = ak.seed_group("engineering")
    alice_pk = ak.seed_user("alice", email="alice@example.com")
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    result = _run("--apply", "--only", "memberships", report_path=tmp_path / "r.json")
    assert result.exit_code == 0, result.output
    assert ak.create_group_calls == 0
    assert ak.create_user_calls == 0
    assert ak.add_user_calls == [(group_pk, alice_pk)]


def test_only_roles_writes_the_assignment_without_memberships_in_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """.chief/milestone-2/_contract/01-role-mapping.md: "--only roles
    covers a realm role and its assignments; there is no separate
    role-assignments selector." This is the one documented exception to
    "selecting one never implicitly writes another kind" -- the assignment
    is reported as kind "membership", but the trigger is "roles" alone.
    """
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    role_pk = ak.seed_group("custom-role", role_origin=True)
    alice_pk = ak.seed_user("alice", email="alice@example.com")
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    result = _run("--apply", "--only", "roles", report_path=tmp_path / "r.json")
    assert result.exit_code == 0, result.output
    assert ak.create_group_calls == 0  # role matched, not created
    assert ak.create_user_calls == 0
    assert ak.add_user_calls == [(role_pk, alice_pk)]
    assert "memberships" in result.output  # visible on stdout, per diagnostics.md


def test_only_memberships_never_reads_role_mappings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The converse of the above: "roles" absent from --only means role
    assignments are not selected either -- --only memberships is group
    memberships only.
    """
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    ak.seed_group("engineering")
    ak.seed_user("alice", email="alice@example.com")
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    result = _run("--apply", "--only", "memberships", report_path=tmp_path / "r.json")
    assert result.exit_code == 0, result.output
    assert not any(path.endswith("/role-mappings/realm") for _, path in kc_requests)
    assert not any(path.endswith("/roles") for _, path in kc_requests)


def test_only_clients_writes_only_the_client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    result = _run(
        "--apply",
        "--only",
        "clients",
        "--authorization-flow",
        AUTH_FLOW_SLUG,
        "--invalidation-flow",
        INV_FLOW_SLUG,
        report_path=tmp_path / "r.json",
    )
    assert result.exit_code == 0, result.output
    assert ak.create_group_calls == 0
    assert ak.create_user_calls == 0
    assert ak.add_user_calls == []
    assert ak.create_provider_calls == 0  # empty client fixture -- nothing to create


def test_subset_excludes_unselected_kinds(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A subset (not a single value): groups+users selected, everything
    else -- including roles and memberships -- must stay silent and unwritten.
    """
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    result = _run("--apply", "--only", "groups,users", report_path=tmp_path / "r.json")
    assert result.exit_code == 0, result.output
    assert ak.create_group_calls == 1
    assert ak.create_user_calls == 2
    assert ak.add_user_calls == []
    assert not any(path.endswith("/roles") for _, path in kc_requests)
    assert "roles" not in result.output
    assert "memberships" not in result.output
    assert "idps" not in result.output
    assert "links" not in result.output


# --- Processing order enforced regardless of --only order.


def test_processing_order_enforced_regardless_of_only_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    # Deliberately scrambled, the reverse of the contract's fixed order.
    result = _run(
        "--apply",
        "--only",
        "clients,federated-links,memberships,roles,users,groups,idps",
        "--authorization-flow",
        AUTH_FLOW_SLUG,
        "--invalidation-flow",
        INV_FLOW_SLUG,
        report_path=tmp_path / "r.json",
    )
    assert result.exit_code == 0, result.output
    paths = [p for _, p in kc_requests]

    def first_index(suffix: str) -> int:
        return next(i for i, p in enumerate(paths) if p.endswith(suffix))

    idps_i = first_index("/identity-provider/instances")
    groups_i = first_index("/groups")
    roles_i = first_index("/roles")
    users_i = first_index("/users")
    members_i = first_index("/members")
    role_mappings_i = first_index("/role-mappings/realm")
    clients_i = first_index("/clients")

    assert idps_i < groups_i < roles_i < users_i < members_i < role_mappings_i < clients_i


# --- Counts reconcile against entities across old and new kinds, in one run.


def test_counts_reconcile_across_old_and_new_kinds_in_one_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    ak = FakeAuthentik()
    kc_requests: list[tuple[str, str]] = []
    _patch_clients(monkeypatch, ak=ak, kc_requests=kc_requests)
    report_path = tmp_path / "r.json"
    result = _run(
        "--apply",
        "--only",
        "idps,groups,roles,users,memberships,federated-links,clients",
        "--authorization-flow",
        AUTH_FLOW_SLUG,
        "--invalidation-flow",
        INV_FLOW_SLUG,
        report_path=report_path,
    )
    assert result.exit_code == 0, result.output
    report = json.loads(report_path.read_text())
    total_counted = sum(sum(kind.values()) for kind in report["counts"].values())
    assert total_counted == len(report["entities"])
    assert report["counts"]["groups"]["created"] == 1
    assert report["counts"]["roles"]["created"] == 1
    assert report["counts"]["users"]["created"] == 2
    # 1 group membership (alice/engineering) + 1 role assignment
    # (alice/custom-role) -- both kind "membership"
    # (.chief/milestone-2/_contract/01-role-mapping.md).
    assert report["counts"]["memberships"]["created"] == 2
    assert report["counts"]["idps"] == {
        "created": 0,
        "skipped": 0,
        "updated": 0,
        "conflict": 0,
        "failed": 0,
    }
    assert report["counts"]["links"] == report["counts"]["idps"]
    kinds = {e["kind"] for e in report["entities"]}
    assert kinds == {"group", "role", "user", "membership"}
