"""Exact stdout formatting from
.chief/milestone-1/_contract/01-cli-interface.md's example block. CLI-level
exit-0/1 behaviour is proven at the report.exit_code unit level
(tests/test_report.py) rather than through a full network-backed CLI
invocation -- see that file's docstring context. Exit 2/3 are already
covered end-to-end in test_cli_usage_errors.py.
"""

from __future__ import annotations

from kc2ak.cli import _count_line, _recovery_line
from kc2ak.migrator import CONFLICT, CREATED, SKIPPED, UPDATED, EntityResult


def _results(created: int, skipped: int, conflict: int, updated: int = 0) -> list[EntityResult]:
    results = []
    for i in range(created):
        results.append(EntityResult("group", f"c{i}", f"c{i}", None, CREATED))
    for i in range(skipped):
        results.append(EntityResult("group", f"s{i}", f"s{i}", None, SKIPPED))
    for i in range(conflict):
        results.append(EntityResult("group", f"x{i}", f"x{i}", None, CONFLICT))
    for i in range(updated):
        results.append(EntityResult("group", f"u{i}", f"u{i}", None, UPDATED))
    return results


def test_count_line_matches_contract_example() -> None:
    assert (
        _count_line("groups", _results(12, 0, 0)) == "groups      12 create,   0 skip,  0 conflict"
    )
    assert (
        _count_line("users", _results(847, 3, 2)) == "users      847 create,   3 skip,  2 conflict"
    )
    assert (
        _count_line("clients", _results(9, 0, 1)) == "clients      9 create,   0 skip,  1 conflict"
    )


def test_count_line_without_update_existing_is_byte_for_byte_unchanged() -> None:
    # Some UPDATED entities exist (e.g. a prior --update-existing run's
    # results reused here), but without the flag the column must not appear.
    results = _results(12, 0, 0, updated=5)
    assert _count_line("groups", results) == "groups      12 create,   0 skip,  0 conflict"
    assert _count_line("groups", results, update_existing=False) == (
        "groups      12 create,   0 skip,  0 conflict"
    )


def test_count_line_with_update_existing_adds_update_column() -> None:
    # .chief/milestone-1/_contract/01-cli-interface.md amendment: the column
    # is visible on stdout, not only in the report, since modifying
    # pre-existing objects is the one thing --update-existing exists to permit.
    results = _results(0, 0, 0, updated=12)
    assert _count_line("groups", results, update_existing=True) == (
        "groups       0 create,   0 skip,  12 update,  0 conflict"
    )


def test_count_line_matches_contract_example_for_new_rows() -> None:
    # .chief/milestone-2/_contract/03-cli-and-report-extensions.md's example
    # block -- same _count_line, new labels ("idps", "roles", "links").
    assert _count_line("idps", _results(2, 0, 1)) == "idps         2 create,   0 skip,  1 conflict"
    assert _count_line("roles", _results(8, 0, 2)) == "roles        8 create,   0 skip,  2 conflict"
    assert (
        _count_line("links", _results(210, 0, 4)) == "links      210 create,   0 skip,  4 conflict"
    )


def test_recovery_line_matches_contract_example() -> None:
    line = _recovery_line({"eligible": 847, "no_email_address": 0})
    assert line == "recovery mail would be sent to 847 users (0 lack an email address)"


def test_recovery_line_prints_even_when_zero() -> None:
    # Mandatory on every dry run per the contract, even with zero recipients.
    line = _recovery_line({"eligible": 0, "no_email_address": 0})
    assert line == "recovery mail would be sent to 0 users (0 lack an email address)"
