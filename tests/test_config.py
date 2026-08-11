import pytest

from kc2ak import redact as redact_mod
from kc2ak.config import Config
from kc2ak.errors import UsageError


def setup_function() -> None:
    redact_mod._secrets.clear()


def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KC_URL", "http://kc.example")
    monkeypatch.setenv("AK_URL", "http://ak.example")
    monkeypatch.setenv("AK_TOKEN", "ak-token-value")
    for var in ("KC_REALM_ADMIN", "KC_ADMIN_PASSWORD", "KC_CLIENT_ID", "KC_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)


def test_from_env_with_password_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    monkeypatch.setenv("KC_REALM_ADMIN", "admin")
    monkeypatch.setenv("KC_ADMIN_PASSWORD", "admin-pw")

    cfg = Config.from_env()

    assert cfg.kc_url == "http://kc.example"
    assert cfg.kc_realm_admin == "admin"
    assert cfg.kc_admin_password == "admin-pw"
    assert cfg.ak_token == "ak-token-value"


def test_from_env_with_client_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    monkeypatch.setenv("KC_CLIENT_ID", "svc")
    monkeypatch.setenv("KC_CLIENT_SECRET", "svc-secret")

    cfg = Config.from_env()

    assert cfg.kc_client_id == "svc"
    assert cfg.kc_client_secret == "svc-secret"


def test_from_env_missing_kc_credentials_raises_usage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _base_env(monkeypatch)

    with pytest.raises(UsageError):
        Config.from_env()


def test_from_env_missing_required_var_raises_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    monkeypatch.delenv("KC_URL", raising=False)
    monkeypatch.setenv("KC_REALM_ADMIN", "admin")
    monkeypatch.setenv("KC_ADMIN_PASSWORD", "admin-pw")

    with pytest.raises(UsageError, match="KC_URL"):
        Config.from_env()


def test_from_env_registers_secrets_for_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    _base_env(monkeypatch)
    monkeypatch.setenv("KC_REALM_ADMIN", "admin")
    monkeypatch.setenv("KC_ADMIN_PASSWORD", "super-secret-pw")

    Config.from_env()

    assert "super-secret-pw" in redact_mod._secrets
    assert "ak-token-value" in redact_mod._secrets
