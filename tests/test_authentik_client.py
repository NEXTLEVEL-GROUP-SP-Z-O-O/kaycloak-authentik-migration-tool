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


def test_recovery_flow_configured_true_when_default_brand_has_flow() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v3/core/brands/"
        return httpx.Response(
            200,
            json={
                "results": [
                    {"default": True, "flow_recovery": "11111111-1111-1111-1111-111111111111"}
                ]
            },
        )

    client = AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(handler)
    )
    assert client.recovery_flow_configured() is True


def test_recovery_flow_configured_false_when_flow_recovery_null() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": [{"default": True, "flow_recovery": None}]})

    client = AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(handler)
    )
    assert client.recovery_flow_configured() is False


def test_recovery_flow_configured_false_when_no_brands() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": []})

    client = AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(handler)
    )
    assert client.recovery_flow_configured() is False


def test_get_email_stage_returns_stage_when_found() -> None:
    stage_uuid = "22222222-2222-2222-2222-222222222222"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/api/v3/stages/email/{stage_uuid}/"
        return httpx.Response(200, json={"pk": stage_uuid, "use_global_settings": True})

    client = AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(handler)
    )
    stage = client.get_email_stage(stage_uuid)
    assert stage is not None
    assert stage["pk"] == stage_uuid


def test_get_email_stage_returns_none_on_404() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "Not found."})

    client = AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(handler)
    )
    assert client.get_email_stage("bogus") is None


def test_send_recovery_email_uses_query_param_not_body() -> None:
    # Confirmed live against authentik 2024.10.5: email_stage is a query
    # parameter. The body form in _contract/03-entity-mapping.md's example
    # 400s with "Email stage does not exist" even for a real stage.
    stage_uuid = "33333333-3333-3333-3333-333333333333"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v3/core/users/42/recovery_email/"
        assert request.url.params["email_stage"] == stage_uuid
        assert request.content == b""
        return httpx.Response(204)

    client = AuthentikClient(
        "http://ak.example", "ak-token", transport=httpx.MockTransport(handler)
    )
    response = client.send_recovery_email(42, stage_uuid)
    assert response.status_code == 204
