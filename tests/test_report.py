"""Report building, exit codes, and recovery-mail counting
(.chief/milestone-1/_contract/02-report-schema.md,
.chief/milestone-1/_contract/01-cli-interface.md).
"""

from __future__ import annotations

import json
from pathlib import Path

from kc2ak import redact as redact_mod
from kc2ak.migrator import CONFLICT, CREATED, FAILED, SKIPPED, UPDATED, EntityResult
from kc2ak.report import (
    build_report,
    compute_recovery_mail,
    eligible_for_recovery_mail,
    exit_code,
    write_report,
)


def setup_function() -> None:
    redact_mod._secrets.clear()


def _entities() -> list[EntityResult]:
    return [
        EntityResult("group", "g1", "engineering", "pk-1", CREATED),
        EntityResult("group", "g2", "sales", None, CONFLICT, "nested_groups_unsupported"),
        EntityResult(
            "user", "u1", "jkowalski", 1042, CREATED, email="j@example.com", is_active=True
        ),
        EntityResult(
            "user", "u2", "mnowak", None, CONFLICT, "username_taken_email_differs", email="m@x.com"
        ),
        EntityResult("user", "u3", "adisabled", 7, CREATED, email="", is_active=False),
        EntityResult("membership", "g1:u1", "engineering/jkowalski", "pk-1", CREATED),
        EntityResult("membership", "g1:u9", "engineering/failed", None, FAILED, "api_rejected"),
    ]


def test_counts_reconcile_against_entities() -> None:
    report = build_report(
        realm="x",
        applied=True,
        started_at="2026-08-11T09:00:00Z",
        finished_at="2026-08-11T09:01:00Z",
        entities=_entities(),
        recovery_mail=compute_recovery_mail(_entities()),
    )
    total_counted = sum(sum(kind.values()) for kind in report["counts"].values())
    assert total_counted == len(report["entities"]) == len(_entities())
    assert report["counts"]["groups"] == {
        "created": 1,
        "skipped": 0,
        "updated": 0,
        "conflict": 1,
        "failed": 0,
    }
    assert report["counts"]["clients"] == {
        "created": 0,
        "skipped": 0,
        "updated": 0,
        "conflict": 0,
        "failed": 0,
    }


def test_every_entity_appears_exactly_once() -> None:
    entities = _entities()
    report = build_report(
        realm="x",
        applied=False,
        started_at="t0",
        finished_at="t1",
        entities=entities,
        recovery_mail=compute_recovery_mail(entities),
    )
    assert len(report["entities"]) == len(entities)
    refs = [(e["kind"], e["keycloak_id"]) for e in report["entities"]]
    assert len(refs) == len(set(refs))


def test_dry_run_and_applied_reports_identical_shape() -> None:
    entities = _entities()
    dry = build_report(
        realm="x",
        applied=False,
        started_at="t0",
        finished_at="t1",
        entities=entities,
        recovery_mail=compute_recovery_mail(entities),
    )
    applied = build_report(
        realm="x",
        applied=True,
        started_at="t0",
        finished_at="t1",
        entities=entities,
        recovery_mail=compute_recovery_mail(entities),
    )
    assert dry.keys() == applied.keys()
    assert [e.keys() for e in dry["entities"]] == [e.keys() for e in applied["entities"]]
    assert dry["applied"] is False
    assert all(e["authentik_ref"] is None for e in dry["entities"])
    # An applied run does have real refs for entities that were actually
    # matched/created (e.g. the CREATED group has pk-1) -- only the dry run
    # forces them null.
    assert any(e["authentik_ref"] is not None for e in applied["entities"])


def test_exit_code_zero_when_clean() -> None:
    clean = [
        EntityResult("group", "g1", "engineering", "pk-1", CREATED),
        EntityResult("user", "u1", "jkowalski", 1042, SKIPPED),
    ]
    assert exit_code(clean) == 0


def test_exit_code_one_on_conflict() -> None:
    entities = [EntityResult("group", "g2", "sales", None, CONFLICT, "nested_groups_unsupported")]
    assert exit_code(entities) == 1


def test_exit_code_one_on_failed() -> None:
    entities = [EntityResult("membership", "m1", "g/u", None, FAILED, "api_rejected")]
    assert exit_code(entities) == 1


def test_exit_code_one_on_unmapped_alone() -> None:
    """The subtle one (_goal/03-idempotency-and-matching.md): an entity with
    no conflict and no failure -- CREATED, nothing wrong -- still forces
    exit 1 if part of it was silently dropped as unmapped. A green exit must
    be impossible when a token's contents were dropped.
    """
    entities = [
        EntityResult(
            "client",
            "c1",
            "billing-api",
            "billing-api",
            CREATED,
            None,
            unmapped=[
                {
                    "type": "protocol_mapper",
                    "name": "cost-centre",
                    "mapper_type": "oidc-script-based-protocol-mapper",
                    "why": "mapper type not in whitelist",
                }
            ],
        )
    ]
    assert all(e.outcome not in (CONFLICT, FAILED) for e in entities)
    assert exit_code(entities) == 1


def test_compute_recovery_mail_partitions_created_users() -> None:
    entities = [
        EntityResult("user", "u1", "a", 1, CREATED, email="a@x.com", is_active=True),
        EntityResult("user", "u2", "b", 2, CREATED, email="", is_active=True),
        EntityResult("user", "u3", "c", 3, CREATED, email="c@x.com", is_active=False),
        # Not CREATED -- must not count toward any bucket.
        EntityResult("user", "u4", "d", 4, SKIPPED, email="d@x.com", is_active=True),
    ]
    recovery = compute_recovery_mail(entities)
    assert recovery == {
        "requested": False,
        "eligible": 1,
        "sent": 0,
        "no_email_address": 1,
        "inactive_excluded": 1,
    }


def test_eligible_for_recovery_mail_excludes_non_created_outcomes() -> None:
    """_goal/02-safety-and-blast-radius.md's "who receives mail" rule: only
    CREATED users this run made are ever mail candidates -- SKIPPED/UPDATED
    already have a way in, CONFLICT/FAILED have no account to reset.
    """
    entities = [
        EntityResult("user", "u1", "created", 1, CREATED, email="a@x.com", is_active=True),
        EntityResult("user", "u2", "skipped", 2, SKIPPED, email="b@x.com", is_active=True),
        EntityResult("user", "u3", "updated", 3, UPDATED, email="c@x.com", is_active=True),
        EntityResult("user", "u4", "conflict", None, CONFLICT, email="d@x.com", is_active=True),
        EntityResult("user", "u5", "failed", None, FAILED, email="e@x.com", is_active=True),
        EntityResult("user", "u6", "no-email", 6, CREATED, email="", is_active=True),
        EntityResult("user", "u7", "inactive", 7, CREATED, email="g@x.com", is_active=False),
        EntityResult("group", "g1", "not-a-user", 1, CREATED),
    ]
    eligible = eligible_for_recovery_mail(entities)
    assert [r.keycloak_ref for r in eligible] == ["created"]


def test_compute_recovery_mail_requested_and_sent_are_wired_through() -> None:
    entities = [
        EntityResult("user", "u1", "a", 1, CREATED, email="a@x.com", is_active=True),
    ]
    recovery = compute_recovery_mail(entities, requested=True, sent=1)
    assert recovery == {
        "requested": True,
        "eligible": 1,
        "sent": 1,
        "no_email_address": 0,
        "inactive_excluded": 0,
    }


def test_compute_recovery_mail_defaults_match_task3_placeholders() -> None:
    # Callers that never send mail (e.g. --send-recovery-email not passed)
    # get the same requested=False/sent=0 shape task-3 hardcoded.
    entities = [EntityResult("user", "u1", "a", 1, CREATED, email="a@x.com", is_active=True)]
    assert compute_recovery_mail(entities) == {
        "requested": False,
        "eligible": 1,
        "sent": 0,
        "no_email_address": 0,
        "inactive_excluded": 0,
    }


def test_no_secrets_in_written_report(tmp_path: Path) -> None:
    secret = "super-secret-client-token"
    redact_mod.register_secret(secret)
    entities = [
        EntityResult("client", "c1", "billing-api", None, FAILED, f"api_rejected: {secret}"),
    ]
    report = build_report(
        realm="x",
        applied=True,
        started_at="t0",
        finished_at="t1",
        entities=entities,
        recovery_mail=compute_recovery_mail(entities),
    )
    path = tmp_path / "report.json"
    write_report(path, report)
    text = path.read_text()
    assert secret not in text
    assert json.loads(text)["entities"][0]["reason"] != f"api_rejected: {secret}"
