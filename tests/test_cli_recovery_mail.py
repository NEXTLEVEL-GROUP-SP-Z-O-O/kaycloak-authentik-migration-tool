"""End-to-end recovery-mail behaviour through the CLI
(.chief/milestone-1/_goal/02-safety-and-blast-radius.md, task-4 in
.chief/milestone-1/_plan/_todo.md). KeycloakClient/AuthentikClient are
monkeypatched to real instances backed by httpx.MockTransport, so the whole
migrate() path -- preconditions, migrate_users, the send loop, the report --
runs for real against fakes shaped like the live APIs (recovery_flow via the
default brand's flow_recovery, email_stage via GET /stages/email/{uuid}/,
recovery_email as a query param -- all confirmed live in task-4's
verification pass).
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

VALID_STAGE = "11111111-1111-1111-1111-111111111111"


def setup_function() -> None:
    redact_mod._secrets.clear()


def _kc_handler(users: list[dict[str, Any]]):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "kc-token"})
        first = int(request.url.params.get("first", "0"))
        max_ = int(request.url.params.get("max", "100"))
        if path.endswith("/groups"):
            return httpx.Response(200, json=[])
        if path.endswith("/users"):
            return httpx.Response(200, json=users[first : first + max_])
        raise AssertionError(f"unexpected Keycloak request: {path}")

    return handler


class RecoveryFake:
    """Stands in for Authentik's brands/stages/users/recovery_email
    endpoints, shaped like the live 2024.10.5 responses verified in task-4.
    """

    def __init__(self, *, flow_recovery: str | None = "flow-1") -> None:
        self.flow_recovery = flow_recovery
        self.users: dict[str, dict[str, Any]] = {}
        self._seq = 100
        self.create_user_calls = 0
        self.create_group_calls = 0
        self.recovery_calls: list[tuple[int, str | None]] = []

    def seed_user(self, username: str, email: str, *, is_active: bool = True) -> int:
        self._seq += 1
        self.users[username] = {
            "pk": self._seq,
            "username": username,
            "email": email,
            "is_active": is_active,
        }
        return self._seq

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        if path == "/api/v3/core/users/me/" and method == "GET":
            return httpx.Response(200, json={"user": {"username": "akadmin"}})

        if path == "/api/v3/core/brands/" and method == "GET":
            return httpx.Response(
                200, json={"results": [{"default": True, "flow_recovery": self.flow_recovery}]}
            )

        if path.startswith("/api/v3/stages/email/") and method == "GET":
            stage_uuid = path.removeprefix("/api/v3/stages/email/").removesuffix("/")
            if stage_uuid != VALID_STAGE:
                return httpx.Response(404, json={"detail": "Not found."})
            return httpx.Response(200, json={"pk": stage_uuid, "use_global_settings": True})

        if path == "/api/v3/core/groups/" and method == "GET":
            return httpx.Response(200, json={"results": []})

        if path == "/api/v3/core/groups/" and method == "POST":
            self.create_group_calls += 1
            raise AssertionError("no group should be created in this scenario")

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
            if body["username"] == "willfail":
                return httpx.Response(500, json={"detail": "boom"})
            self._seq += 1
            record = {
                "pk": self._seq,
                "username": body["username"],
                "email": body.get("email", ""),
                "is_active": body.get("is_active", True),
            }
            self.users[body["username"]] = record
            return httpx.Response(201, json=record)

        if path.endswith("/recovery_email/") and method == "POST":
            pk = int(path.removeprefix("/api/v3/core/users/").removesuffix("/recovery_email/"))
            self.recovery_calls.append((pk, request.url.params.get("email_stage")))
            return httpx.Response(204)

        raise AssertionError(f"unexpected Authentik request: {method} {path}")


def _patch_clients(
    monkeypatch: pytest.MonkeyPatch, kc_users: list[dict[str, Any]], fake: RecoveryFake
) -> None:
    kc_handler = _kc_handler(kc_users)

    def kc_factory(base_url: str, **kwargs: Any) -> KeycloakClient:
        kwargs.pop("transport", None)
        return KeycloakClient(base_url, transport=httpx.MockTransport(kc_handler), **kwargs)

    def ak_factory(base_url: str, token: str, **kwargs: Any) -> AuthentikClient:
        kwargs.pop("transport", None)
        return AuthentikClient(
            base_url, token, transport=httpx.MockTransport(fake.handler), **kwargs
        )

    monkeypatch.setattr("kc2ak.cli.KeycloakClient", kc_factory)
    monkeypatch.setattr("kc2ak.cli.AuthentikClient", ak_factory)


def _set_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KC_URL", "http://kc.example")
    monkeypatch.setenv("KC_REALM_ADMIN", "admin")
    monkeypatch.setenv("KC_ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("AK_URL", "http://ak.example")
    monkeypatch.setenv("AK_TOKEN", "ak-token")


_USERS = [
    {
        "id": "u1",
        "username": "created1",
        "email": "c1@example.com",
        "firstName": "C",
        "lastName": "One",
        "enabled": True,
    },
    {
        "id": "u2",
        "username": "created2noemail",
        "firstName": "C",
        "lastName": "Two",
        "enabled": True,
    },
    {
        "id": "u3",
        "username": "createdinactive",
        "email": "ci@example.com",
        "firstName": "C",
        "lastName": "Three",
        "enabled": False,
    },
    {
        "id": "u4",
        "username": "existing",
        "email": "exists@example.com",
        "firstName": "E",
        "lastName": "Xist",
        "enabled": True,
    },
    {
        "id": "u5",
        "username": "willfail",
        "email": "wf@example.com",
        "firstName": "W",
        "lastName": "Fail",
        "enabled": True,
    },
]


def test_apply_alone_sends_zero_mail(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_env(monkeypatch)
    fake = RecoveryFake()
    fake.seed_user("existing", "exists@example.com")
    _patch_clients(monkeypatch, _USERS, fake)
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "migrate",
            "--realm",
            "x",
            "--apply",
            "--only",
            "groups,users,memberships",
            "--report",
            str(report_path),
        ],
    )

    assert fake.recovery_calls == []
    report = json.loads(report_path.read_text())
    assert report["recovery_mail"] == {
        "requested": False,
        "eligible": 1,
        "sent": 0,
        "no_email_address": 1,
        "inactive_excluded": 1,
    }
    assert result.exit_code in (0, 1)


def test_send_recovery_email_only_mails_created_eligible_users(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    fake = RecoveryFake()
    fake.seed_user("existing", "exists@example.com")
    _patch_clients(monkeypatch, _USERS, fake)
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "migrate",
            "--realm",
            "x",
            "--apply",
            "--send-recovery-email",
            "--email-stage",
            VALID_STAGE,
            "--only",
            "groups,users,memberships",
            "--report",
            str(report_path),
        ],
    )

    created1_pk = fake.users["created1"]["pk"]
    # Exactly one recovery mail: the SKIPPED user (existing), the FAILED
    # user (willfail), the inactive user, and the no-email user must never
    # be mailed -- only the single CREATED+active+has-email user is.
    assert fake.recovery_calls == [(created1_pk, VALID_STAGE)]

    report = json.loads(report_path.read_text())
    assert report["recovery_mail"] == {
        "requested": True,
        "eligible": 1,
        "sent": 1,
        "no_email_address": 1,
        "inactive_excluded": 1,
    }
    by_username = {e["keycloak_ref"]: e for e in report["entities"] if e["kind"] == "user"}
    assert by_username["existing"]["outcome"] == "SKIPPED"
    assert by_username["willfail"]["outcome"] == "FAILED"
    assert result.exit_code == 1  # willfail's FAILED outcome forces exit 1


def test_broken_recovery_flow_aborts_before_creating_any_user(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    fake = RecoveryFake(flow_recovery=None)  # brand has no recovery flow configured
    _patch_clients(monkeypatch, _USERS, fake)
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "migrate",
            "--realm",
            "x",
            "--apply",
            "--send-recovery-email",
            "--email-stage",
            VALID_STAGE,
            "--only",
            "groups,users,memberships",
            "--report",
            str(report_path),
        ],
    )

    assert result.exit_code == 2
    assert fake.create_user_calls == 0
    assert fake.create_group_calls == 0
    assert fake.recovery_calls == []
    assert not report_path.exists()
