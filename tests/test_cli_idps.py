"""CLI wiring for identity providers: --idp-secrets / --pre-authentication-flow
usage and precondition errors, the unconditional "created disabled" stdout
line, and the no-secrets-anywhere-in-the-report guarantee
(.chief/milestone-2/_contract/02-idp-mapping.md,
.chief/milestone-2/_contract/03-cli-and-report-extensions.md).
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
FLOW_SLUG = "pre-auth-flow"
FLOW_PK = "33333333-0000-0000-0000-000000000009"
AUTH_FLOW_SLUG = "auth-flow"
AUTH_FLOW_PK = "33333333-0000-0000-0000-00000000000a"
ENROLL_FLOW_SLUG = "enroll-flow"
ENROLL_FLOW_PK = "33333333-0000-0000-0000-00000000000b"
_FLOWS = {FLOW_SLUG: FLOW_PK, AUTH_FLOW_SLUG: AUTH_FLOW_PK, ENROLL_FLOW_SLUG: ENROLL_FLOW_PK}

CORPORATE_SSO = {
    "alias": "corporate-sso",
    "internalId": "idp-1",
    "providerId": "oidc",
    "config": {"clientId": "the-client-id", "clientSecret": "**********"},
}
CORPORATE_SAML = {
    "alias": "corporate-saml",
    "internalId": "idp-2",
    "providerId": "saml",
    "config": {"singleSignOnServiceUrl": "https://saml.example.com/sso"},
}


def setup_function() -> None:
    redact_mod._secrets.clear()


def _kc_handler(idps: list[dict[str, Any]]):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "kc-token"})
        if path.endswith("/mappers"):
            return httpx.Response(200, json=[])
        if path.endswith("/identity-provider/instances"):
            first = int(request.url.params.get("first", "0"))
            max_ = int(request.url.params.get("max", "100"))
            return httpx.Response(200, json=idps[first : first + max_])
        raise AssertionError(f"unexpected Keycloak request: {path}")

    return handler


def _ak_handler(request: httpx.Request, *, created: list[dict[str, Any]]) -> httpx.Response:
    path = request.url.path
    method = request.method
    if path == "/api/v3/core/users/me/" and method == "GET":
        return httpx.Response(200, json={"user": {"username": "akadmin"}})
    if path == "/api/v3/flows/instances/" and method == "GET":
        slug = request.url.params.get("slug")
        pk = _FLOWS.get(slug or "")
        results = [{"pk": pk, "slug": slug}] if pk else []
        return httpx.Response(200, json={"results": results})
    if path == "/api/v3/sources/all/" and method == "GET":
        return httpx.Response(200, json={"results": []})
    if path == "/api/v3/sources/oauth/" and method == "POST":
        body = json.loads(request.content)
        created.append(body)
        return httpx.Response(201, json={"pk": "src-1", **body})
    if path == "/api/v3/sources/saml/" and method == "POST":
        body = json.loads(request.content)
        created.append(body)
        return httpx.Response(201, json={"pk": "src-2", **body})
    if path == "/api/v3/crypto/certificatekeypairs/" and method == "GET":
        return httpx.Response(200, json={"results": []})
    if path == "/api/v3/crypto/certificatekeypairs/" and method == "POST":
        body = json.loads(request.content)
        return httpx.Response(201, json={"pk": "kp-1", "name": body["name"]})
    raise AssertionError(f"unexpected Authentik request: {method} {path}")


def _patch_clients(
    monkeypatch: pytest.MonkeyPatch,
    *,
    idps: list[dict[str, Any]],
    created_sources: list[dict[str, Any]] | None = None,
) -> None:
    kc_handler = _kc_handler(idps)
    created = created_sources if created_sources is not None else []

    def kc_factory(base_url: str, **kwargs: Any) -> KeycloakClient:
        kwargs.pop("transport", None)
        return KeycloakClient(base_url, transport=httpx.MockTransport(kc_handler), **kwargs)

    def ak_factory(base_url: str, token: str, **kwargs: Any) -> AuthentikClient:
        kwargs.pop("transport", None)

        def handler(request: httpx.Request) -> httpx.Response:
            return _ak_handler(request, created=created)

        return AuthentikClient(base_url, token, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr("kc2ak.cli.KeycloakClient", kc_factory)
    monkeypatch.setattr("kc2ak.cli.AuthentikClient", ak_factory)


def _set_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KC_URL", "http://kc.example")
    monkeypatch.setenv("KC_REALM_ADMIN", "admin")
    monkeypatch.setenv("KC_ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("AK_URL", "http://ak.example")
    monkeypatch.setenv("AK_TOKEN", "ak-token")


def _run(*args: str, report_path: Path) -> Any:
    return runner.invoke(app, ["migrate", "--realm", REALM, "--report", str(report_path), *args])


# --- --idp-secrets usage/precondition errors ----------------------------------


def test_idp_secrets_without_idps_in_scope_is_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text("{}")
    secrets_path.chmod(0o600)
    result = _run(
        "--only",
        "groups",
        "--idp-secrets",
        str(secrets_path),
        report_path=tmp_path / "r.json",
    )
    assert result.exit_code == 3


def test_malformed_secrets_file_is_exit_3(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[])
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text("not json")
    secrets_path.chmod(0o600)
    result = _run(
        "--only", "idps", "--idp-secrets", str(secrets_path), report_path=tmp_path / "r.json"
    )
    assert result.exit_code == 3


def test_group_readable_secrets_file_is_exit_3(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[])
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text("{}")
    secrets_path.chmod(0o644)
    result = _run(
        "--only", "idps", "--idp-secrets", str(secrets_path), report_path=tmp_path / "r.json"
    )
    assert result.exit_code == 3


def test_missing_secrets_file_is_exit_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[])
    result = _run(
        "--only",
        "idps",
        "--idp-secrets",
        str(tmp_path / "nope.json"),
        report_path=tmp_path / "r.json",
    )
    assert result.exit_code == 2


def test_missing_pre_authentication_flow_with_saml_in_scope_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SAML])
    result = _run("--apply", "--only", "idps", report_path=tmp_path / "r.json")
    assert result.exit_code == 2


# --- --authentication-flow / --enrollment-flow: optional, unlike --pre-authentication-flow ---


def test_authentication_and_enrollment_flow_unsupplied_is_not_a_precondition_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Unlike --pre-authentication-flow (required, hard exit 2 when a SAML IdP
    # is in scope), these are optional: an OAuth IdP in scope with neither
    # flag must still run clean -- the source is just created disabled
    # (task-5b amendment to .chief/milestone-2/_contract/02-idp-mapping.md).
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO])
    result = _run("--apply", "--only", "idps", report_path=tmp_path / "r.json")
    assert result.exit_code != 2


def test_bogus_authentication_flow_with_oauth_idp_in_scope_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO])
    result = _run(
        "--apply",
        "--only",
        "idps",
        "--authentication-flow",
        "this-flow-does-not-exist",
        report_path=tmp_path / "r.json",
    )
    assert result.exit_code == 2


def test_bogus_enrollment_flow_with_oauth_idp_in_scope_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO])
    result = _run(
        "--apply",
        "--only",
        "idps",
        "--enrollment-flow",
        "this-flow-does-not-exist",
        report_path=tmp_path / "r.json",
    )
    assert result.exit_code == 2


def test_bogus_authentication_flow_with_saml_idp_in_scope_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # task-5c: --authentication-flow/--enrollment-flow now gate SAML sources
    # too, so a bogus slug with only a SAML IdP in scope must exit 2 exactly
    # like the OAuth case above -- SAML is no longer exempt.
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SAML])
    result = _run(
        "--apply",
        "--only",
        "idps",
        "--authentication-flow",
        "this-flow-does-not-exist",
        "--pre-authentication-flow",
        FLOW_SLUG,
        report_path=tmp_path / "r.json",
    )
    assert result.exit_code == 2


def test_bogus_authentication_flow_is_harmless_without_any_supported_idp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Same "unused flag stays harmless" principle already established for
    # --pre-authentication-flow with no SAML IdP in scope -- but now that
    # both OAuth and SAML gate on these flags (task-5c), the flag is only
    # truly unused when neither kind is present, e.g. an unsupported
    # provider (CONFLICT / idp_type_unsupported, never becomes a source).
    _set_env(monkeypatch)
    unsupported_idp = {
        "alias": "linkedin-sso",
        "internalId": "idp-3",
        "providerId": "linkedin-openid-connect",
        "config": {},
    }
    _patch_clients(monkeypatch, idps=[unsupported_idp])
    result = _run(
        "--apply",
        "--only",
        "idps",
        "--authentication-flow",
        "this-flow-does-not-exist",
        report_path=tmp_path / "r.json",
    )
    assert result.exit_code != 2


# --- the unconditional "created disabled" stdout line -------------------------


def test_disabled_line_printed_on_dry_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO])
    result = _run("--only", "idps", report_path=tmp_path / "r.json")
    assert result.exit_code != 3
    assert "1 identity providers created disabled" in result.output


def test_disabled_line_printed_on_apply(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO])
    result = _run("--apply", "--only", "idps", report_path=tmp_path / "r.json")
    assert "1 identity providers created disabled" in result.output


def test_disabled_line_absent_when_secret_supplied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO])
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text(json.dumps({"corporate-sso": "the-real-secret"}))
    secrets_path.chmod(0o600)
    result = _run(
        "--apply",
        "--only",
        "idps",
        "--idp-secrets",
        str(secrets_path),
        "--authentication-flow",
        AUTH_FLOW_SLUG,
        "--enrollment-flow",
        ENROLL_FLOW_SLUG,
        report_path=tmp_path / "r.json",
    )
    assert "created disabled" not in result.output


# --- the flow-missing stdout line (task-5b) ------------------------------------


def test_flow_missing_line_printed_even_with_a_working_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO])
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text(json.dumps({"corporate-sso": "the-real-secret"}))
    secrets_path.chmod(0o600)
    result = _run(
        "--apply",
        "--only",
        "idps",
        "--idp-secrets",
        str(secrets_path),
        report_path=tmp_path / "r.json",
    )
    assert "no secret supplied" not in result.output
    assert "authentication/enrollment flow not supplied" in result.output


def test_flow_missing_line_absent_when_both_flows_supplied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO])
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text(json.dumps({"corporate-sso": "the-real-secret"}))
    secrets_path.chmod(0o600)
    result = _run(
        "--apply",
        "--only",
        "idps",
        "--idp-secrets",
        str(secrets_path),
        "--authentication-flow",
        AUTH_FLOW_SLUG,
        "--enrollment-flow",
        ENROLL_FLOW_SLUG,
        report_path=tmp_path / "r.json",
    )
    assert "flow not supplied" not in result.output


# --- no secret ever reaches the report or stdout ------------------------------


def test_secret_never_appears_in_report_or_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO])
    secret_value = "kc2ak-live-test-secret-xyz"
    secrets_path = tmp_path / "secrets.json"
    secrets_path.write_text(json.dumps({"corporate-sso": secret_value}))
    secrets_path.chmod(0o600)
    report_path = tmp_path / "r.json"
    result = _run(
        "--apply",
        "--only",
        "idps",
        "--idp-secrets",
        str(secrets_path),
        report_path=report_path,
    )
    assert secret_value not in result.output
    assert secret_value not in report_path.read_text()


# --- --idp-user-matching: stands in for the links authentik's API can't write ---


def test_idp_user_matching_defaults_to_username_link(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    created: list[dict[str, Any]] = []
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO], created_sources=created)
    result = _run("--apply", "--only", "idps", report_path=tmp_path / "r.json")
    assert result.exit_code != 3
    assert created[0]["user_matching_mode"] == "username_link"


def test_idp_user_matching_flag_overrides(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_env(monkeypatch)
    created: list[dict[str, Any]] = []
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO], created_sources=created)
    _run(
        "--apply",
        "--only",
        "idps",
        "--idp-user-matching",
        "email_link",
        report_path=tmp_path / "r.json",
    )
    assert created[0]["user_matching_mode"] == "email_link"


def test_idp_user_matching_identifier_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    created: list[dict[str, Any]] = []
    _patch_clients(monkeypatch, idps=[CORPORATE_SSO], created_sources=created)
    _run(
        "--apply",
        "--only",
        "idps",
        "--idp-user-matching",
        "identifier",
        report_path=tmp_path / "r.json",
    )
    assert created[0]["user_matching_mode"] == "identifier"


def test_idp_user_matching_rejects_unknown_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_env(monkeypatch)
    _patch_clients(monkeypatch, idps=[])
    result = _run("--only", "idps", "--idp-user-matching", "bogus", report_path=tmp_path / "r.json")
    assert result.exit_code == 3
