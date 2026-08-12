"""Preconditions checked before any write. See
.chief/milestone-1/_goal/02-safety-and-blast-radius.md. task-1 covered
credential validity, authorization/invalidation flow existence, and
--email-stage presence; task-4 adds the recovery-mail-specific checks: a
recovery flow on the brand, the --email-stage UUID resolving to a real
stage, and that stage looking SMTP-configured.
"""

from __future__ import annotations

from kc2ak.authentik_client import AuthentikAuthError, AuthentikClient
from kc2ak.errors import PreconditionError
from kc2ak.keycloak_client import KeycloakAuthError, KeycloakClient
from kc2ak.mappers.idps import source_kind


def check_preconditions(
    *,
    kc_client: KeycloakClient,
    ak_client: AuthentikClient,
    clients_in_scope: bool,
    authorization_flow: str | None,
    invalidation_flow: str | None,
    send_recovery_email: bool,
    email_stage: str | None,
    idps_in_scope: bool = False,
    realm: str = "",
    pre_authentication_flow: str | None = None,
    authentication_flow: str | None = None,
    enrollment_flow: str | None = None,
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

    if idps_in_scope and any(
        idp["providerId"] == "saml" for idp in kc_client.get_identity_providers(realm)
    ):
        # --pre-authentication-flow is only required when a SAML IdP is
        # actually present -- the same conditional shape as
        # --authorization-flow, required only when clients are
        # (.chief/milestone-2/_contract/03-cli-and-report-extensions.md).
        # Whether one is present can only be known by reading Keycloak, so
        # unlike the clients flows this can't be checked from the flag alone.
        if not pre_authentication_flow:
            raise PreconditionError(
                "--pre-authentication-flow is required when a SAML identity provider is in scope"
            )
        if not ak_client.flow_exists(pre_authentication_flow):
            raise PreconditionError(
                f"pre-authentication flow {pre_authentication_flow!r} does not exist"
            )

    if idps_in_scope and any(
        source_kind(idp["providerId"]) is not None
        for idp in kc_client.get_identity_providers(realm)
    ):
        # Unlike --pre-authentication-flow, --authentication-flow/
        # --enrollment-flow are optional: a source (OAuth or SAML, task-5c
        # widened this to both) can be created without them (neither
        # OAuthSourceRequest nor SAMLSourceRequest requires them), it is
        # just written disabled -- .chief/milestone-2/_contract/02-idp-mapping.md's
        # task-5b/task-5c amendments. So there is nothing to check when the
        # operator never supplied one; a *supplied* slug that doesn't
        # resolve is still an exit-2 precondition failure, the same as every
        # other flow flag in this contract.
        if authentication_flow and not ak_client.flow_exists(authentication_flow):
            raise PreconditionError(f"authentication flow {authentication_flow!r} does not exist")
        if enrollment_flow and not ak_client.flow_exists(enrollment_flow):
            raise PreconditionError(f"enrollment flow {enrollment_flow!r} does not exist")

    if send_recovery_email:
        assert email_stage is not None
        if not ak_client.recovery_flow_configured():
            raise PreconditionError("no recovery flow is configured on the authentik brand")

        stage = ak_client.get_email_stage(email_stage)
        if stage is None:
            raise PreconditionError(f"email stage {email_stage!r} does not exist")
        if not (stage.get("use_global_settings") or stage.get("host")):
            raise PreconditionError(f"email stage {email_stage!r} has no SMTP configuration")
