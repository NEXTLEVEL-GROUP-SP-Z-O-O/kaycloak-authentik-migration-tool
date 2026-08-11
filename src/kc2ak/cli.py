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
from kc2ak.keycloak_client import KeycloakClient
from kc2ak.migrator import (
    CONFLICT,
    CREATED,
    SKIPPED,
    UPDATED,
    EntityResult,
    migrate_groups,
    migrate_memberships,
    migrate_users,
)
from kc2ak.preconditions import check_preconditions
from kc2ak.redact import redact
from kc2ak.report import build_report, compute_recovery_mail, write_report
from kc2ak.report import exit_code as report_exit_code

# typer's own parsing errors (unknown option, missing argument, bad choice)
# default to exit code 2, which collides with this contract's "aborted on a
# precondition" meaning. Force them into the "usage error" bucket instead.
# typer vendors click as `typer._click`, so that's what actually needs
# patching (a top-level `click` install would not affect typer's parsing).
ClickUsageError.exit_code = 3

app = typer.Typer(add_completion=False)

_ALL_ENTITY_TYPES = ("groups", "users", "memberships", "clients")
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
    update_existing: bool = typer.Option(
        False, "--update-existing", help="PATCH matched objects instead of skipping them"
    ),
    report: Path = typer.Option(
        _DEFAULT_REPORT_PATH, "--report", help="Where the machine-readable report is written"
    ),
    only: str | None = typer.Option(
        None, "--only", help="Restrict to groups,users,memberships,clients (comma-separated)"
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
        if clients_in_scope and (not authorization_flow or not invalidation_flow):
            raise UsageError(
                "--authorization-flow and --invalidation-flow are required unless "
                "--only excludes clients"
            )
        cfg = Config.from_env()
    except UsageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=3) from None

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

        # Preconditions passed. groups/users/memberships now actually
        # migrate, in the fixed order the goal requires; clients (providers,
        # applications, protocol mappers) are task-5, so that line still
        # reports zero.
        need_groups = "groups" in scope or "memberships" in scope
        need_users = "users" in scope or "memberships" in scope
        # A group/user pass run only to support memberships (not itself in
        # --only) must never write -- --only memberships means "match
        # against what an earlier run already created," not "create groups
        # and users I explicitly scoped out."
        groups_apply = apply and "groups" in scope
        users_apply = apply and "users" in scope

        group_results: list[EntityResult] = []
        user_results: list[EntityResult] = []
        membership_results: list[EntityResult] = []
        ok_groups: dict[str, str] = {}
        group_pks: dict[str, str] = {}
        group_members: dict[str, set[int]] = {}
        user_pks: dict[str, int] = {}
        resolved_usernames: set[str] = set()

        if need_groups:
            group_results, ok_groups, group_pks, group_members = migrate_groups(
                kc_client, ak_client, realm, apply=groups_apply, update_existing=update_existing
            )
        if need_users:
            user_results, user_pks, resolved_usernames = migrate_users(
                kc_client, ak_client, realm, apply=users_apply, update_existing=update_existing
            )
        if "memberships" in scope:
            membership_results = migrate_memberships(
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

        if "groups" in scope:
            typer.echo(_count_line("groups", group_results, update_existing=update_existing))
        if "users" in scope:
            typer.echo(_count_line("users", user_results, update_existing=update_existing))
        if "memberships" in scope:
            typer.echo(
                _count_line("memberships", membership_results, update_existing=update_existing)
            )
        if "clients" in scope:
            typer.echo(_count_line("clients", [], update_existing=update_existing))

        recovery_mail = compute_recovery_mail(user_results)
        typer.echo(_recovery_line(recovery_mail))
        if not apply:
            typer.echo("dry run — nothing written. re-run with --apply")

        finished_at = _now_iso()
        entities = [*group_results, *user_results, *membership_results]
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
