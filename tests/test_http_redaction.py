"""HTTP debug logging must never contain secrets, per
.chief/milestone-1/_goal/02-safety-and-blast-radius.md's Secrets section.
"""

import logging

import httpx
import pytest

from kc2ak.http import build_client, request_with_retry
from kc2ak.redact import register_secret


def setup_function() -> None:
    from kc2ak import redact as redact_mod

    redact_mod._secrets.clear()


def test_debug_log_redacts_authorization_header_and_body_secret(
    caplog: pytest.LogCaptureFixture,
) -> None:
    register_secret("super-secret-password")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    client = build_client(
        "http://example.test",
        headers={"Authorization": "Bearer super-secret-password"},
        transport=httpx.MockTransport(handler),
    )
    with caplog.at_level(logging.DEBUG, logger="kc2ak.http"):
        request_with_retry(
            client,
            "POST",
            "/token",
            data={"password": "super-secret-password"},
        )

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "super-secret-password" not in log_text
    assert "[REDACTED]" in log_text


def test_retry_on_transient_5xx_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("kc2ak.http.time.sleep", lambda _seconds: None)
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] < 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})

    client = build_client("http://example.test", transport=httpx.MockTransport(handler))
    response = request_with_retry(client, "GET", "/x")

    assert response.status_code == 200
    assert attempts["n"] == 2


def test_gives_up_after_max_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("kc2ak.http.time.sleep", lambda _seconds: None)
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        return httpx.Response(500)

    client = build_client("http://example.test", transport=httpx.MockTransport(handler))
    response = request_with_retry(client, "GET", "/x")

    assert response.status_code == 500
    assert attempts["n"] == 3
