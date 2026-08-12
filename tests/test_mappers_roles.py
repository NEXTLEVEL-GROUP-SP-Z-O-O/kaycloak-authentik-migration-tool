"""Fixture-backed tests for the roles mapper. tests/fixtures/kc_roles.json,
kc_user_role_mappings_*.json and kc_client_roles_*.json are real Keycloak 25
admin API responses captured from a live instance seeded from
deploy/keycloak/realm-kc2ak-test.json.
"""

import json
from pathlib import Path
from typing import Any

from kc2ak.mappers.roles import (
    KC2AK_ORIGIN_REALM_ROLE,
    builtin_role_names,
    is_composite,
    is_role_origin,
    map_role,
    unmapped_client_roles,
    unmapped_role_fields,
)

FIXTURES = Path(__file__).parent / "fixtures"
REALM = "kc2ak-test"


def _roles() -> dict[str, dict[str, Any]]:
    data = json.loads((FIXTURES / "kc_roles.json").read_text())
    return {r["name"]: r for r in data}


def _user_roles(username: str) -> list[dict[str, Any]]:
    data = json.loads((FIXTURES / f"kc_user_role_mappings_{username}.json").read_text())
    return list(data)


def test_builtin_role_names_includes_realm_specific_default_roles() -> None:
    names = builtin_role_names(REALM)
    assert "default-roles-kc2ak-test" in names
    assert "offline_access" in names
    assert "uma_authorization" in names
    # not present on every realm, must not be swept in by a loose match
    assert "employee" not in names


def test_plain_role_is_not_composite() -> None:
    assert is_composite(_roles()["employee"]) is False


def test_composite_role_detected_from_the_list_flag() -> None:
    # GET /roles already carries composite: true|false -- detecting it never
    # requires reading /composites (.chief/milestone-2/_contract/01-role-mapping.md).
    assert _roles()["senior-engineer"]["composite"] is True
    assert is_composite(_roles()["senior-engineer"]) is True


def test_default_roles_realm_role_is_composite() -> None:
    # default-roles-{realm} is composite on every realm -- this is exactly
    # why it must be excluded by name before the read is counted, per
    # .chief/milestone-2/_goal/01-roles-scope.md.
    assert is_composite(_roles()["default-roles-kc2ak-test"]) is True


def test_map_role_copies_name_and_stamps_origin() -> None:
    payload = map_role(_roles()["employee"])
    assert payload["name"] == "employee"
    assert payload["attributes"]["kc2ak_origin"] == KC2AK_ORIGIN_REALM_ROLE
    assert payload["attributes"]["keycloak_id"] == _roles()["employee"]["id"]


def test_is_role_origin_true_only_for_matching_marker() -> None:
    migrated = {"pk": "g1", "name": "employee", "attributes": {"kc2ak_origin": "realm_role"}}
    plain_group = {"pk": "g2", "name": "engineering", "attributes": {}}
    other_origin = {"pk": "g3", "name": "x", "attributes": {"kc2ak_origin": "something_else"}}
    assert is_role_origin(migrated) is True
    assert is_role_origin(plain_group) is False
    assert is_role_origin(other_origin) is False


def test_unmapped_role_fields_reports_description_when_present() -> None:
    entries = unmapped_role_fields(_roles()["employee"])
    assert entries == [{"type": "role_field", "name": "description", "why": "not carried over"}]


def test_unmapped_role_fields_empty_without_a_description() -> None:
    assert unmapped_role_fields({"id": "r1", "name": "no-desc"}) == []


def test_user_role_mappings_are_direct_assignments_not_composite_expanded() -> None:
    # Amendment (task-1, then reconfirmed live here): role-mappings/realm
    # returns ajones's direct assignment to the composite senior-engineer
    # itself, never its constituents employee/code-reviewer.
    names = {r["name"] for r in _user_roles("ajones")}
    assert names == {"senior-engineer"}


def test_noemail_users_only_assignment_is_the_seeded_builtin_role() -> None:
    # The seed gap task-2 closes: a realm-file-imported user otherwise gets
    # no default-roles-{realm} assignment at all, so built-in filtering was
    # previously only exercisable at the realm level. noemail's seeded
    # offline_access assignment covers the user level.
    names = {r["name"] for r in _user_roles("noemail")}
    assert names == {"offline_access"}
    assert names <= builtin_role_names(REALM)


def test_unmapped_client_roles_reports_every_role_never_migrated() -> None:
    client_roles = json.loads((FIXTURES / "kc_client_roles_confidential_app.json").read_text())
    entries = unmapped_client_roles(client_roles)
    assert entries == [
        {"type": "client_role", "name": "admin", "why": "client roles are not migrated"}
    ]


def test_unmapped_client_roles_empty_for_no_roles() -> None:
    assert unmapped_client_roles([]) == []
