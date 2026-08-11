import httpx
import pytest

from kc2ak.authentik_client import AuthentikAuthError, AuthentikClient


def test_authenticate_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v3/core/users/me/"
        assert request.headers["authorization"] == "Bearer ak-token"
        return httpx.Response(200, json={"user": {"username": "akadmin"}})

    client = AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(handler)
    )
    client.authenticate()  # should not raise


def test_authenticate_rejected_raises_and_redacts_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="invalid token: ak-token")

    client = AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(AuthentikAuthError) as exc_info:
        client.authenticate()

    assert "ak-token" not in str(exc_info.value)


def test_flow_exists_true_when_results_nonempty() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v3/flows/instances/"
        assert request.url.params["slug"] == "default-provider-authorization-explicit-consent"
        return httpx.Response(
            200, json={"results": [{"slug": "default-provider-authorization-explicit-consent"}]}
        )

    client = AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(handler)
    )
    assert client.flow_exists("default-provider-authorization-explicit-consent") is True


def test_flow_exists_false_when_results_empty() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": []})

    client = AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(handler)
    )
    assert client.flow_exists("nonexistent-flow") is False
