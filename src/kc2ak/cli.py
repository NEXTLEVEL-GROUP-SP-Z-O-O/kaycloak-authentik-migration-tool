"""Typer entrypoint. Flag surface is the full contract from
.chief/milestone-1/_contract/01-cli-interface.md; flags a later task owns are
parsed here and passed through, not implemented.

Usage/config problems are validated by hand (not via typer's `required=`) so
that failures map to the contract's exit codes rather than click's own
defaults: 3 for usage/config errors, 2 for preconditions, both raised before
any client touches the network where possible.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import typer
from typer._click.exceptions import UsageError as ClickUsageError

from kc2ak.authentik_client import AuthentikClient
from kc2ak.config import Config
from kc2ak.errors import PreconditionError, UsageError
from kc2ak.idp_secrets import read_idp_secrets
from kc2ak.keycloak_client import KeycloakClient
from kc2ak.mappers.idps import DEFAULT_USER_MATCHING_MODE, IDP_SECRET_MISSING, USER_MATCHING_MODES
from kc2ak.migrator import (
    CONFLICT,
    CREATED,
    SKIPPED,
    UPDATED,
    EntityResult,
    migrate_clients,
    migrate_federated_links,
    migrate_groups,
    migrate_idps,
    migrate_memberships,
    migrate_role_assignments,
    migrate_roles,
    migrate_users,
)
from kc2ak.preconditions import check_preconditions
from kc2ak.redact import redact
from kc2ak.report import (
    build_report,
    compute_recovery_mail,
    eligible_for_recovery_mail,
    write_report,
)
from kc2ak.report import exit_code as report_exit_code

# typer's own parsing errors (unknown option, missing argument, bad choice)
# default to exit code 2, which collides with this contract's "aborted on a
# precondition" meaning. Force them into the "usage error" bucket instead.
# typer vendors click as `typer._click`, so that's what actually needs
# patching (a top-level `click` install would not affect typer's parsing).
ClickUsageError.exit_code = 3

app = typer.Typer(add_completion=False)

# In the fixed processing order from
# .chief/milestone-2/_contract/03-cli-and-report-extensions.md: idps -> groups
# -> roles -> users -> memberships -> role assignments -> federated links ->
# clients. Role assignments are not a separate value here -- they are
# `--only roles`'s job, per .chief/milestone-2/_contract/01-role-mapping.md.
# "idps" and "federated-links" are parsed and gated like every other kind, but
# have no migrator behind them yet (task-4/task-5); they always produce zero
# entities until then.
_ALL_ENTITY_TYPES = (
    "idps",
    "groups",
    "roles",
    "users",
    "memberships",
    "federated-links",
    "clients",
)
_DEFAULT_REPORT_PATH = Path("./kc2ak-report.json")


@app.callback()
def _main() -> None:
    """kc2ak — migrate one Keycloak realm into Authentik."""
    # Present so typer keeps `migrate` as a named subcommand (per the CLI
    # contract) instead of collapsing the single command to the top level.


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _count_line(entity: str, results: list[EntityResult], *, update_existing: bool = False) -> str:
    created = sum(1 for r in results if r.outcome == CREATED)
    skipped = sum(1 for r in results if r.outcome == SKIPPED)
    conflict = sum(1 for r in results if r.outcome == CONFLICT)
    line = f"{entity:<11}{created:>3} create, {skipped:>3} skip, "
    if update_existing:
        updated = sum(1 for r in results if r.outcome == UPDATED)
        line += f"{updated:>3} update, "
    return line + f"{conflict:>2} conflict"


def _recovery_line(recovery_mail: dict[str, Any]) -> str:
    # Mandatory on every dry run, even when --send-recovery-email was never
    # passed -- task-4 implements the actual mailing, this just counts and
    # reports who would receive it.
    return (
        f"recovery mail would be sent to {recovery_mail['eligible']} users "
        f"({recovery_mail['no_email_address']} lack an email address)"
    )


def _parse_only(value: str | None) -> tuple[str, ...]:
    if value is None:
        return _ALL_ENTITY_TYPES
    chosen = tuple(v.strip() for v in value.split(",") if v.strip())
    invalid = [v for v in chosen if v not in _ALL_ENTITY_TYPES]
    if invalid:
        raise UsageError(
            f"--only: invalid value(s) {invalid}; choose from {', '.join(_ALL_ENTITY_TYPES)}"
        )
    return chosen


@app.command()
def migrate(
    realm: str | None = typer.Option(None, "--realm", help="Keycloak realm to read"),
    apply: bool = typer.Option(
        False, "--apply", help="Enable writes. Without it the run is read-only"
    ),
    send_recovery_email: bool = typer.Option(
        False, "--send-recovery-email", help="Send password-reset mail. Requires --apply"
    ),
    email_stage: str | None = typer.Option(
        None, "--email-stage", help="Authentik email stage UUID. Required by --send-recovery-email"
    ),
    authorization_flow: str | None = typer.Option(
        None, "--authorization-flow", help="Flow assigned to every created OAuth2 provider"
    ),
    invalidation_flow: str | None = typer.Option(
        None, "--invalidation-flow", help="Flow assigned to every created OAuth2 provider"
    ),
    idp_secrets: Path | None = typer.Option(
        None, "--idp-secrets", help="Path to a JSON file mapping IdP alias -> secret"
    ),
    pre_authentication_flow: str | None = typer.Option(
        None, "--pre-authentication-flow", help="Flow assigned to every created SAML source"
    ),
    idp_user_matching: str = typer.Option(
        DEFAULT_USER_MATCHING_MODE,
        "--idp-user-matching",
        help=(
            "How a created/updated source matches a returning user, since authentik's API "
            "cannot pre-create the per-user link: username_link (default), email_link, identifier"
        ),
    ),
    update_existing: bool = typer.Option(
        False, "--update-existing", help="PATCH matched objects instead of skipping them"
    ),
    report: Path = typer.Option(
        _DEFAULT_REPORT_PATH, "--report", help="Where the machine-readable report is written"
    ),
    only: str | None = typer.Option(
        None,
        "--only",
        help=(
            "Restrict to idps,groups,roles,users,memberships,federated-links,clients "
            "(comma-separated)"
        ),
    ),
) -> None:
    """Migrate one Keycloak realm into Authentik."""
    try:
        if not realm:
            raise UsageError("--realm is required")
        if send_recovery_email and not apply:
            raise UsageError("--send-recovery-email requires --apply")
        scope = _parse_only(only)
        clients_in_scope = "clients" in scope
        idps_in_scope = "idps" in scope
        if clients_in_scope and (not authorization_flow or not invalidation_flow):
            raise UsageError(
                "--authorization-flow and --invalidation-flow are required unless "
                "--only excludes clients"
            )
        if idp_secrets is not None and not idps_in_scope:
            raise UsageError("--idp-secrets requires idps in --only scope")
        if idp_user_matching not in USER_MATCHING_MODES:
            raise UsageError(
                f"--idp-user-matching: invalid value {idp_user_matching!r}; "
                f"choose from {', '.join(USER_MATCHING_MODES)}"
            )
        cfg = Config.from_env()
        idp_secrets_map: dict[str, str] = {}
        if idp_secrets is not None and idps_in_scope:
            idp_secrets_map = read_idp_secrets(idp_secrets)
    except UsageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=3) from None
    except PreconditionError as exc:
        # Only read_idp_secrets can reach a PreconditionError this early --
        # a missing/unreadable file is an environment problem, not a usage
        # one, per .chief/milestone-2/_contract/03-cli-and-report-extensions.md.
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from None

    kc_client = KeycloakClient(
        cfg.kc_url,
        realm_admin=cfg.kc_realm_admin,
        admin_password=cfg.kc_admin_password,
        client_id=cfg.kc_client_id,
        client_secret=cfg.kc_client_secret,
    )
    ak_client = AuthentikClient(cfg.ak_url, cfg.ak_token)
    try:
        try:
            check_preconditions(
                kc_client=kc_client,
                ak_client=ak_client,
                clients_in_scope=clients_in_scope,
                authorization_flow=authorization_flow,
                invalidation_flow=invalidation_flow,
                send_recovery_email=send_recovery_email,
                email_stage=email_stage,
                idps_in_scope=idps_in_scope,
                realm=realm,
                pre_authentication_flow=pre_authentication_flow,
            )
        except PreconditionError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from None
        except httpx.HTTPError as exc:
            # Network failure or bad response talking to either endpoint —
            # e.g. wrong URL, endpoint down. Nothing was written.
            typer.echo(f"error: {redact(str(exc))}", err=True)
            raise typer.Exit(code=2) from None

        started_at = _now_iso()

        # Preconditions passed. Entity kinds now actually migrate, in the
        # fixed order .chief/milestone-2/_contract/03-cli-and-report-extensions.md
        # requires regardless of the order --only listed them in: idps ->
        # groups -> roles -> users -> memberships -> role assignments ->
        # federated links -> clients. federated-links never writes anything --
        # authentik's API cannot pre-create these links at all (see
        # migrate_federated_links) -- it only reports.
        idps_apply = apply and idps_in_scope
        need_groups = "groups" in scope or "memberships" in scope
        need_roles = "roles" in scope
        # A role's own creation never needs users (it matches/creates a
        # group directly against Authentik); its assignments do, so "roles"
        # joins "users"/"memberships" as a reason the users pass has to run.
        need_users = "users" in scope or "memberships" in scope or "roles" in scope
        # A group/user/role pass run only to support memberships or role
        # assignments (not itself in --only) must never write -- e.g.
        # --only memberships means "match against what an earlier run
        # already created," not "create groups and users I explicitly
        # scoped out." --only roles covers a role *and* its assignments
        # (.chief/milestone-2/_contract/01-role-mapping.md) -- there is no
        # separate role-assignments selector, so both are gated on "roles".
        groups_apply = apply and "groups" in scope
        roles_apply = apply and "roles" in scope
        users_apply = apply and "users" in scope
        clients_apply = apply and clients_in_scope

        group_results: list[EntityResult] = []
        role_results: list[EntityResult] = []
        user_results: list[EntityResult] = []
        group_membership_results: list[EntityResult] = []
        role_assignment_results: list[EntityResult] = []
        client_results: list[EntityResult] = []
        idp_results: list[EntityResult] = []
        link_results: list[EntityResult] = []
        ok_groups: dict[str, str] = {}
        group_pks: dict[str, str] = {}
        group_members: dict[str, set[int]] = {}
        role_pks: dict[str, str] = {}
        role_conflicted: set[str] = set()
        role_members: dict[str, set[int]] = {}
        user_pks: dict[str, int] = {}
        resolved_usernames: set[str] = set()

        if idps_in_scope:
            idp_results = migrate_idps(
                kc_client,
                ak_client,
                realm,
                apply=idps_apply,
                update_existing=update_existing,
                secrets=idp_secrets_map,
                pre_authentication_flow=pre_authentication_flow,
                user_matching_mode=idp_user_matching,
            )
        if need_groups:
            group_results, ok_groups, group_pks, group_members = migrate_groups(
                kc_client, ak_client, realm, apply=groups_apply, update_existing=update_existing
            )
        if need_roles:
            role_results, role_pks, role_conflicted, role_members = migrate_roles(
                kc_client,
                ak_client,
                realm,
                apply=roles_apply,
                update_existing=update_existing,
                planned_group_names=frozenset(ok_groups),
            )
        if need_users:
            user_results, user_pks, resolved_usernames = migrate_users(
                kc_client, ak_client, realm, apply=users_apply, update_existing=update_existing
            )
        if "memberships" in scope:
            group_membership_results = migrate_memberships(
                kc_client,
                ak_client,
                realm,
                apply=apply,
                ok_groups=ok_groups,
                group_pks=group_pks,
                group_members=group_members,
                user_pks=user_pks,
                resolved_usernames=resolved_usernames,
            )
        if need_roles:
            role_assignment_results = migrate_role_assignments(
                kc_client,
                ak_client,
                realm,
                apply=roles_apply,
                role_pks=role_pks,
                role_conflicted=role_conflicted,
                role_members=role_members,
                user_pks=user_pks,
                resolved_usernames=resolved_usernames,
            )
        if "federated-links" in scope:
            link_results = migrate_federated_links(
                kc_client,
                ak_client,
                realm,
                idp_results=idp_results,
                user_matching_mode=idp_user_matching,
            )
        if clients_in_scope:
            assert authorization_flow is not None
            assert invalidation_flow is not None
            client_results = migrate_clients(
                kc_client,
                ak_client,
                realm,
                apply=clients_apply,
                authorization_flow=authorization_flow,
                invalidation_flow=invalidation_flow,
                update_existing=update_existing,
            )

        # Role assignments are `kind: "membership"`, not their own kind
        # (.chief/milestone-2/_contract/01-role-mapping.md) -- combined here
        # so the "memberships" row/counts reconcile against both sources.
        membership_results = group_membership_results + role_assignment_results

        if "idps" in scope:
            typer.echo(_count_line("idps", idp_results, update_existing=update_existing))
            disabled_count = sum(
                1
                for r in idp_results
                if r.kind == "idp"
                and r.outcome == CREATED
                and any(u["type"] == IDP_SECRET_MISSING for u in r.unmapped)
            )
            if disabled_count:
                # Unconditional on --apply, same as the recovery-mail line --
                # a dry run must show this too, or it promises a plan it
                # doesn't fully disclose
                # (.chief/milestone-2/_contract/03-cli-and-report-extensions.md).
                typer.echo(
                    f"{disabled_count} identity providers created disabled — no secret supplied"
                )
        if "groups" in scope:
            typer.echo(_count_line("groups", group_results, update_existing=update_existing))
        if "roles" in scope:
            typer.echo(_count_line("roles", role_results, update_existing=update_existing))
        if "users" in scope:
            typer.echo(_count_line("users", user_results, update_existing=update_existing))
        # "memberships" or "roles" -- the latter can write membership
        # entities (role assignments) with "memberships" absent from
        # --only, and that effect must be visible on stdout where it
        # happened (.chief/_rules/_standard/diagnostics.md).
        if "memberships" in scope or "roles" in scope:
            typer.echo(
                _count_line("memberships", membership_results, update_existing=update_existing)
            )
        if "federated-links" in scope:
            typer.echo(_count_line("links", link_results, update_existing=update_existing))
        if clients_in_scope:
            typer.echo(_count_line("clients", client_results, update_existing=update_existing))

        # Only reachable under --apply (usage error otherwise), so eligible
        # CREATED users have a real Authentik pk -- except when --only
        # excludes "users" while --apply is set, in which case the users
        # pass ran dry-run-shaped to support memberships and never actually
        # created anyone; skip those rather than mail a pk that doesn't exist.
        sent = 0
        if send_recovery_email:
            assert email_stage is not None
            for result in eligible_for_recovery_mail(user_results):
                if not isinstance(result.authentik_ref, int):
                    continue
                try:
                    mail_response = ak_client.send_recovery_email(result.authentik_ref, email_stage)
                except httpx.HTTPError:
                    continue
                if mail_response.status_code == 204:
                    sent += 1

        recovery_mail = compute_recovery_mail(
            user_results, requested=send_recovery_email, sent=sent
        )
        typer.echo(_recovery_line(recovery_mail))
        if not apply:
            typer.echo("dry run — nothing written. re-run with --apply")

        finished_at = _now_iso()
        entities = [
            *idp_results,
            *group_results,
            *role_results,
            *user_results,
            *membership_results,
            *link_results,
            *client_results,
        ]
        report_data = build_report(
            realm=realm,
            applied=apply,
            started_at=started_at,
            finished_at=finished_at,
            entities=entities,
            recovery_mail=recovery_mail,
        )
        write_report(report, report_data)
        raise typer.Exit(code=report_exit_code(entities))
    finally:
        kc_client.close()
        ak_client.close()


if __name__ == "__main__":
    app()
