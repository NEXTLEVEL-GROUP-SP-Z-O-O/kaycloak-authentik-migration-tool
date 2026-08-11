import httpx
import pytest

from kc2ak import redact as redact_mod
from kc2ak.keycloak_client import KeycloakAuthError, KeycloakClient


def setup_function() -> None:
    redact_mod._secrets.clear()


def test_authenticate_password_grant_sets_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/realms/master/protocol/openid-connect/token"
        body = request.read().decode()
        assert "grant_type=password" in body
        assert "username=admin" in body
        return httpx.Response(200, json={"access_token": "kc-access-token"})

    client = KeycloakClient(
        "http://kc.example",
        realm_admin="admin",
        admin_password="admin-pw",
        transport=httpx.MockTransport(handler),
    )
    client.authenticate()

    assert "kc-access-token" in redact_mod._secrets


def test_authenticate_client_credentials_grant() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode()
        assert "grant_type=client_credentials" in body
        return httpx.Response(200, json={"access_token": "svc-token"})

    client = KeycloakClient(
        "http://kc.example",
        client_id="svc",
        client_secret="svc-secret",
        transport=httpx.MockTransport(handler),
    )
    client.authenticate()


def test_authenticate_rejected_raises_and_redacts_secret() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="invalid_grant: bad password admin-pw")

    client = KeycloakClient(
        "http://kc.example",
        realm_admin="admin",
        admin_password="admin-pw",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(KeycloakAuthError) as exc_info:
        client.authenticate()

    assert "admin-pw" not in str(exc_info.value)
    assert "[REDACTED]" in str(exc_info.value)


def test_get_users_paginates_with_first_and_max() -> None:
    seen_params: list[tuple[int, int]] = []
    page_size = 2
    all_users = [{"id": str(i), "username": f"user{i}"} for i in range(5)]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "tok"})
        first = int(request.url.params["first"])
        max_ = int(request.url.params["max"])
        seen_params.append((first, max_))
        return httpx.Response(200, json=all_users[first : first + max_])

    client = KeycloakClient(
        "http://kc.example",
        realm_admin="admin",
        admin_password="admin-pw",
        transport=httpx.MockTransport(handler),
    )
    client.authenticate()
    users = list(client.get_users("kc2ak-test", page_size=page_size))

    assert users == all_users
    assert seen_params == [(0, 2), (2, 2), (4, 2)]


def test_get_users_empty_realm_yields_nothing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "tok"})
        return httpx.Response(200, json=[])

    client = KeycloakClient(
        "http://kc.example",
        realm_admin="admin",
        admin_password="admin-pw",
        transport=httpx.MockTransport(handler),
    )
    client.authenticate()

    assert list(client.get_users("empty-realm")) == []


def test_get_users_before_authenticate_raises() -> None:
    client = KeycloakClient(
        "http://kc.example",
        realm_admin="admin",
        admin_password="admin-pw",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[])),
    )
    with pytest.raises(KeycloakAuthError):
        list(client.get_users("kc2ak-test"))
