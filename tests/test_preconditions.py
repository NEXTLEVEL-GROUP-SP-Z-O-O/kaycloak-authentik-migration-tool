from unittest.mock import MagicMock

import pytest

from kc2ak.authentik_client import AuthentikAuthError
from kc2ak.errors import PreconditionError
from kc2ak.keycloak_client import KeycloakAuthError
from kc2ak.preconditions import check_preconditions


def _clients() -> tuple[MagicMock, MagicMock]:
    kc = MagicMock()
    ak = MagicMock()
    ak.flow_exists.return_value = True
    ak.recovery_flow_configured.return_value = True
    ak.get_email_stage.return_value = {"use_global_settings": True}
    return kc, ak


def test_all_preconditions_pass() -> None:
    kc, ak = _clients()

    check_preconditions(
        kc_client=kc,
        ak_client=ak,
        clients_in_scope=True,
        authorization_flow="authz",
        invalidation_flow="inval",
        send_recovery_email=False,
        email_stage=None,
    )

    kc.authenticate.assert_called_once()
    ak.authenticate.assert_called_once()
    ak.flow_exists.assert_any_call("authz")
    ak.flow_exists.assert_any_call("inval")


def test_keycloak_credentials_invalid_raises_precondition_error() -> None:
    kc, ak = _clients()
    kc.authenticate.side_effect = KeycloakAuthError("nope")

    with pytest.raises(PreconditionError, match="Keycloak credentials invalid"):
        check_preconditions(
            kc_client=kc,
            ak_client=ak,
            clients_in_scope=False,
            authorization_flow=None,
            invalidation_flow=None,
            send_recovery_email=False,
            email_stage=None,
        )
    ak.authenticate.assert_not_called()


def test_authentik_credentials_invalid_raises_precondition_error() -> None:
    kc, ak = _clients()
    ak.authenticate.side_effect = AuthentikAuthError("nope")

    with pytest.raises(PreconditionError, match="Authentik credentials invalid"):
        check_preconditions(
            kc_client=kc,
            ak_client=ak,
            clients_in_scope=False,
            authorization_flow=None,
            invalidation_flow=None,
            send_recovery_email=False,
            email_stage=None,
        )


def test_missing_authorization_flow_raises_precondition_error() -> None:
    kc, ak = _clients()
    ak.flow_exists.side_effect = lambda slug: slug != "missing-authz"

    with pytest.raises(PreconditionError, match="authorization flow"):
        check_preconditions(
            kc_client=kc,
            ak_client=ak,
            clients_in_scope=True,
            authorization_flow="missing-authz",
            invalidation_flow="inval",
            send_recovery_email=False,
            email_stage=None,
        )


def test_missing_invalidation_flow_raises_precondition_error() -> None:
    kc, ak = _clients()
    ak.flow_exists.side_effect = lambda slug: slug != "missing-inval"

    with pytest.raises(PreconditionError, match="invalidation flow"):
        check_preconditions(
            kc_client=kc,
            ak_client=ak,
            clients_in_scope=True,
            authorization_flow="authz",
            invalidation_flow="missing-inval",
            send_recovery_email=False,
            email_stage=None,
        )


def test_flows_not_checked_when_clients_out_of_scope() -> None:
    kc, ak = _clients()

    check_preconditions(
        kc_client=kc,
        ak_client=ak,
        clients_in_scope=False,
        authorization_flow=None,
        invalidation_flow=None,
        send_recovery_email=False,
        email_stage=None,
    )

    ak.flow_exists.assert_not_called()


def test_send_recovery_email_without_email_stage_raises_precondition_error() -> None:
    kc, ak = _clients()

    with pytest.raises(PreconditionError, match="--email-stage"):
        check_preconditions(
            kc_client=kc,
            ak_client=ak,
            clients_in_scope=False,
            authorization_flow=None,
            invalidation_flow=None,
            send_recovery_email=True,
            email_stage=None,
        )
    # fails before any network call
    kc.authenticate.assert_not_called()


def test_send_recovery_email_with_email_stage_passes() -> None:
    kc, ak = _clients()

    check_preconditions(
        kc_client=kc,
        ak_client=ak,
        clients_in_scope=False,
        authorization_flow=None,
        invalidation_flow=None,
        send_recovery_email=True,
        email_stage="11111111-1111-1111-1111-111111111111",
    )
    ak.recovery_flow_configured.assert_called_once()
    ak.get_email_stage.assert_called_once_with("11111111-1111-1111-1111-111111111111")


def test_recovery_checks_not_made_when_send_recovery_email_false() -> None:
    kc, ak = _clients()

    check_preconditions(
        kc_client=kc,
        ak_client=ak,
        clients_in_scope=False,
        authorization_flow=None,
        invalidation_flow=None,
        send_recovery_email=False,
        email_stage=None,
    )
    ak.recovery_flow_configured.assert_not_called()
    ak.get_email_stage.assert_not_called()


def test_no_recovery_flow_on_brand_raises_precondition_error() -> None:
    kc, ak = _clients()
    ak.recovery_flow_configured.return_value = False

    with pytest.raises(PreconditionError, match="no recovery flow"):
        check_preconditions(
            kc_client=kc,
            ak_client=ak,
            clients_in_scope=False,
            authorization_flow=None,
            invalidation_flow=None,
            send_recovery_email=True,
            email_stage="11111111-1111-1111-1111-111111111111",
        )
    ak.get_email_stage.assert_not_called()


def test_unknown_email_stage_raises_precondition_error() -> None:
    kc, ak = _clients()
    ak.get_email_stage.return_value = None

    with pytest.raises(PreconditionError, match="does not exist"):
        check_preconditions(
            kc_client=kc,
            ak_client=ak,
            clients_in_scope=False,
            authorization_flow=None,
            invalidation_flow=None,
            send_recovery_email=True,
            email_stage="11111111-1111-1111-1111-111111111111",
        )


def test_email_stage_without_smtp_configuration_raises_precondition_error() -> None:
    kc, ak = _clients()
    ak.get_email_stage.return_value = {"use_global_settings": False, "host": ""}

    with pytest.raises(PreconditionError, match="SMTP"):
        check_preconditions(
            kc_client=kc,
            ak_client=ak,
            clients_in_scope=False,
            authorization_flow=None,
            invalidation_flow=None,
            send_recovery_email=True,
            email_stage="11111111-1111-1111-1111-111111111111",
        )


def test_email_stage_with_stage_level_host_passes_smtp_check() -> None:
    kc, ak = _clients()
    ak.get_email_stage.return_value = {"use_global_settings": False, "host": "smtp.example.com"}

    check_preconditions(
        kc_client=kc,
        ak_client=ak,
        clients_in_scope=False,
        authorization_flow=None,
        invalidation_flow=None,
        send_recovery_email=True,
        email_stage="11111111-1111-1111-1111-111111111111",
    )
