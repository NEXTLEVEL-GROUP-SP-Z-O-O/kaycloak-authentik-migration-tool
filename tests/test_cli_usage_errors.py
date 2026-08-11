"""Usage/config errors must exit 3 without ever touching the network.
Precondition failures (needing live clients) are covered by preconditions
tests and the live verification steps, not here.
"""

import httpx
import pytest
from typer.testing import CliRunner

from kc2ak import redact as redact_mod
from kc2ak.cli import app

runner = CliRunner()


def setup_function() -> None:
    redact_mod._secrets.clear()


def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "KC_URL",
        "KC_REALM_ADMIN",
        "KC_ADMIN_PASSWORD",
        "KC_CLIENT_ID",
        "KC_CLIENT_SECRET",
        "AK_URL",
        "AK_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)


def test_missing_realm_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    result = runner.invoke(app, ["migrate"])
    assert result.exit_code == 3


def test_send_recovery_email_without_apply_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    result = runner.invoke(
        app, ["migrate", "--realm", "x", "--send-recovery-email", "--only", "groups"]
    )
    assert result.exit_code == 3
    assert "--apply" in result.output


def test_invalid_only_value_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    result = runner.invoke(app, ["migrate", "--realm", "x", "--only", "bogus"])
    assert result.exit_code == 3


def test_missing_flows_when_clients_in_scope_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    result = runner.invoke(app, ["migrate", "--realm", "x"])
    assert result.exit_code == 3
    assert "authorization-flow" in result.output


def test_flows_not_required_when_only_excludes_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    # still fails, but on missing KC_URL (config), not on the flow flags
    result = runner.invoke(app, ["migrate", "--realm", "x", "--only", "groups,users"])
    assert result.exit_code == 3
    assert "KC_URL" in result.output


def test_missing_kc_credentials_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv("KC_URL", "http://kc.example")
    monkeypatch.setenv("AK_URL", "http://ak.example")
    monkeypatch.setenv("AK_TOKEN", "tok")
    result = runner.invoke(app, ["migrate", "--realm", "x", "--only", "groups"])
    assert result.exit_code == 3
    assert "credentials" in result.output


def test_unknown_flag_exits_3_not_clicks_default_2(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    result = runner.invoke(app, ["migrate", "--realm", "x", "--no-such-flag"])
    assert result.exit_code == 3


def test_unreachable_endpoint_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    # A precondition-phase network failure (host down, wrong URL) must not
    # crash with Python's default exit 1 — nothing was written, so it's a
    # precondition failure per the contract.
    _clean_env(monkeypatch)
    monkeypatch.setenv("KC_URL", "http://127.0.0.1:1")  # nothing listens here
    monkeypatch.setenv("KC_REALM_ADMIN", "admin")
    monkeypatch.setenv("KC_ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("AK_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("AK_TOKEN", "tok")
    result = runner.invoke(app, ["migrate", "--realm", "x", "--only", "groups"])
    assert result.exit_code == 2
    assert not isinstance(result.exception, httpx.HTTPError)
