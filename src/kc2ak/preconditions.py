"""Preconditions checked before any write. See
.chief/milestone-1/_goal/02-safety-and-blast-radius.md and task-1's scope:
only credential validity, flow existence, and --email-stage presence are
checked here — recovery-flow/SMTP validation is task-4.
"""

from __future__ import annotations

from kc2ak.authentik_client import AuthentikAuthError, AuthentikClient
from kc2ak.errors import PreconditionError
from kc2ak.keycloak_client import KeycloakAuthError, KeycloakClient


def check_preconditions(
    *,
    kc_client: KeycloakClient,
    ak_client: AuthentikClient,
    clients_in_scope: bool,
    authorization_flow: str | None,
    invalidation_flow: str | None,
    send_recovery_email: bool,
    email_stage: str | None,
) -> None:
    """Run every precondition, raising PreconditionError on the first
    failure. Nothing is written to Authentik before or during this call.
    """
    if send_recovery_email and not email_stage:
        raise PreconditionError("--email-stage is required when --send-recovery-email is set")

    try:
        kc_client.authenticate()
    except KeycloakAuthError as exc:
        raise PreconditionError(f"Keycloak credentials invalid: {exc}") from None

    try:
        ak_client.authenticate()
    except AuthentikAuthError as exc:
        raise PreconditionError(f"Authentik credentials invalid: {exc}") from None

    if clients_in_scope:
        assert authorization_flow is not None
        assert invalidation_flow is not None
        if not ak_client.flow_exists(authorization_flow):
            raise PreconditionError(f"authorization flow {authorization_flow!r} does not exist")
        if not ak_client.flow_exists(invalidation_flow):
            raise PreconditionError(f"invalidation flow {invalidation_flow!r} does not exist")
