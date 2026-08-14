"""Builds and writes the JSON report from
.chief/milestone-1/_contract/02-report-schema.md, and derives the CLI exit
code from the same entity list so the two can never disagree.

Consumes migrator.py's in-memory EntityResult records; does not touch how
they are produced.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kc2ak.migrator import CONFLICT, CREATED, FAILED, EntityResult
from kc2ak.redact import redact

_KIND_TO_KEY = {
    "group": "groups",
    "user": "users",
    "membership": "memberships",
    "client": "clients",
    "role": "roles",
    "idp": "idps",
    "federated_link": "links",
}
_OUTCOME_TO_KEY = {
    "CREATED": "created",
    "SKIPPED": "skipped",
    "UPDATED": "updated",
    "CONFLICT": "conflict",
    "FAILED": "failed",
}


def _build_counts(entities: list[EntityResult]) -> dict[str, dict[str, int]]:
    counts = {
        key: {"created": 0, "skipped": 0, "updated": 0, "conflict": 0, "failed": 0}
        for key in _KIND_TO_KEY.values()
    }
    for entity in entities:
        counts[_KIND_TO_KEY[entity.kind]][_OUTCOME_TO_KEY[entity.outcome]] += 1
    total_counted = sum(sum(kind_counts.values()) for kind_counts in counts.values())
    # Contract: "counts must reconcile against entities; a mismatch is a
    # bug" -- assert it rather than hoping, per the task brief.
    assert total_counted == len(entities), "report counts do not reconcile against entities"
    return counts


def eligible_for_recovery_mail(user_results: list[EntityResult]) -> list[EntityResult]:
    """Users this run CREATED, active, with an email address --
    _goal/02-safety-and-blast-radius.md's "who receives mail" rule: only an
    outcome of CREATED has a fresh Authentik account to reset (SKIPPED/
    UPDATED already had a way in, CONFLICT/FAILED have no account at all),
    and inactive/no-email users are excluded from the mail pass entirely.

    cli.py's send loop and compute_recovery_mail()'s eligible/sent counts
    both derive from this one list, so a SKIPPED/UPDATED/CONFLICT/FAILED
    user cannot be mailed by construction, not by convention.
    """
    return [
        r
        for r in user_results
        if r.kind == "user" and r.outcome == CREATED and r.is_active and r.email
    ]


def compute_recovery_mail(
    user_results: list[EntityResult], *, requested: bool = False, sent: int = 0
) -> dict[str, Any]:
    """Partitions this run's CREATED users into eligible / no-email /
    inactive-excluded, per _goal/02-safety-and-blast-radius.md: only
    users this run created can receive mail, disabled users are excluded
    entirely, and users with no email address can't be mailed at all.
    `requested`/`sent` default to task-3's placeholders for callers that
    never send mail; cli.py passes the real values once it has actually run
    (or skipped) the send pass.
    """
    created = [r for r in user_results if r.kind == "user" and r.outcome == CREATED]
    inactive_excluded = sum(1 for r in created if not r.is_active)
    no_email_address = sum(1 for r in created if r.is_active and not r.email)
    eligible = eligible_for_recovery_mail(user_results)
    return {
        "requested": requested,
        "eligible": len(eligible),
        "sent": sent,
        "no_email_address": no_email_address,
        "inactive_excluded": inactive_excluded,
    }


def build_report(
    *,
    realm: str,
    applied: bool,
    started_at: str,
    finished_at: str,
    entities: list[EntityResult],
    recovery_mail: dict[str, Any],
) -> dict[str, Any]:
    """Assembles the full report dict. Every entity read from Keycloak must
    appear exactly once in `entities` -- callers pass the concatenation of
    every migrate_*() result list. `authentik_ref` is forced null on a dry
    run: nothing was written, so no ref exists yet, even for a matched
    (SKIPPED/UPDATED) entity whose ref is only known from a read.
    """
    return {
        "version": 1,
        "realm": realm,
        "applied": applied,
        "started_at": started_at,
        "finished_at": finished_at,
        "counts": _build_counts(entities),
        "recovery_mail": recovery_mail,
        "entities": [
            {
                "kind": e.kind,
                "keycloak_id": e.keycloak_id,
                "keycloak_ref": e.keycloak_ref,
                "authentik_ref": e.authentik_ref if applied else None,
                "outcome": e.outcome,
                "reason": e.reason,
                "unmapped": e.unmapped,
            }
            for e in entities
        ],
    }


# The two exceptions to "any unmapped entry gates exit 1": standard_scope_claim
# and (milestone-2) role_field are universal properties of every migration --
# the same three claims drop on every client that declares `profile` or
# `email`, and `description` is unreproducible on every role that has one --
# not per-realm findings an operator needs to review. Gating on them would
# make exit 0 unreachable forever and teach operators to skip past `unmapped`
# -- the same reasoning `unmapped_client_fields` already applies to
# unconditional entries, one level up
# (.chief/milestone-1/_contract/02-report-schema.md,
# .chief/milestone-2/_contract/01-role-mapping.md). Framed as an exception
# (gate unless one of these) rather than an allowlist of gating types, so an
# unknown future `unmapped` type fails loud (exit 1) instead of silently
# defaulting to a green exit
# (.chief/milestone-2/_contract/03-cli-and-report-extensions.md).
_NON_GATING_UNMAPPED_TYPES = frozenset({"standard_scope_claim", "role_field"})


def exit_code(entities: list[EntityResult]) -> int:
    """0 clean, 1 completed with findings -- conflicts, failures, or an
    unmapped entry whose type is not in `_NON_GATING_UNMAPPED_TYPES`
    (.chief/milestone-1/_contract/01-cli-interface.md,
    .chief/milestone-2/_contract/03-cli-and-report-extensions.md).
    """
    has_findings = any(
        e.outcome in (CONFLICT, FAILED)
        or any(u["type"] not in _NON_GATING_UNMAPPED_TYPES for u in e.unmapped)
        for e in entities
    )
    return 1 if has_findings else 0


def write_report(path: Path, report: dict[str, Any]) -> None:
    """No secrets anywhere in the report, including inside reason/unmapped
    -- redact() is applied to the full serialised text as a structural
    guarantee, not just to the fields expected to hold them.
    """
    path.write_text(redact(json.dumps(report, indent=2)) + "\n")
