"""Fixture-backed tests for the group mapper. tests/fixtures/kc_groups.json
is a real GET /admin/realms/{realm}/groups response captured from a live
Keycloak 25 instance seeded from deploy/keycloak/realm-kc2ak-test.json.
"""

import json
from pathlib import Path
from typing import Any

from kc2ak.mappers.groups import is_nested, map_group

FIXTURES = Path(__file__).parent / "fixtures"


def _groups() -> dict[str, dict[str, Any]]:
    data = json.loads((FIXTURES / "kc_groups.json").read_text())
    return {g["name"]: g for g in data}


def test_flat_group_is_not_nested() -> None:
    assert is_nested(_groups()["engineering"]) is False


def test_group_with_subgroup_count_is_nested() -> None:
    # Keycloak 25's list endpoint reports nesting via subGroupCount, not a
    # populated subGroups list -- confirmed against a live instance.
    sales = _groups()["sales"]
    assert sales["subGroups"] == []
    assert sales["subGroupCount"] == 1
    assert is_nested(sales) is True


def test_group_with_populated_subgroups_list_is_also_nested() -> None:
    # realm-export shape (deploy/keycloak/realm-kc2ak-test.json) populates
    # subGroups directly instead of subGroupCount.
    nested = {"id": "x", "name": "sales", "subGroups": [{"name": "admins"}]}
    assert is_nested(nested) is True


def test_map_group_copies_name_and_attributes() -> None:
    payload = map_group(_groups()["engineering"])
    assert payload["name"] == "engineering"


def test_map_group_records_keycloak_id_in_attributes() -> None:
    payload = map_group(_groups()["engineering"])
    assert payload["attributes"]["keycloak_id"] == "11111111-0000-0000-0000-000000000001"


def test_map_group_preserves_existing_attributes() -> None:
    kc_group = {"id": "g1", "name": "eng", "attributes": {"cost_centre": ["1234"]}}
    payload = map_group(kc_group)
    assert payload["attributes"]["cost_centre"] == ["1234"]
    assert payload["attributes"]["keycloak_id"] == "g1"
