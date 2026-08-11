"""Fixture-backed tests for the user mapper. tests/fixtures/kc_users.json is
a real GET /admin/realms/{realm}/users response captured from a live
Keycloak 25 instance seeded from deploy/keycloak/realm-kc2ak-test.json.
"""

import json
from pathlib import Path
from typing import Any

from kc2ak.mappers.users import map_user

FIXTURES = Path(__file__).parent / "fixtures"


def _users() -> dict[str, dict[str, Any]]:
    data = json.loads((FIXTURES / "kc_users.json").read_text())
    return {u["username"]: u for u in data}


def test_map_user_combines_first_and_last_name() -> None:
    payload = map_user(_users()["ajones"])
    assert payload["name"] == "Alice Jones"


def test_map_user_copies_username_and_email() -> None:
    payload = map_user(_users()["ajones"])
    assert payload["username"] == "ajones"
    assert payload["email"] == "alice@example.com"


def test_map_user_enabled_true_is_active() -> None:
    assert map_user(_users()["ajones"])["is_active"] is True


def test_map_user_disabled_becomes_inactive() -> None:
    # disableduser has enabled: false in the seed realm.
    payload = map_user(_users()["disableduser"])
    assert payload["is_active"] is False


def test_map_user_missing_email_maps_to_empty_string() -> None:
    # noemail has no `email` key at all in the real Keycloak response.
    assert "email" not in _users()["noemail"]
    payload = map_user(_users()["noemail"])
    assert payload["email"] == ""


def test_map_user_records_keycloak_id_in_attributes() -> None:
    payload = map_user(_users()["ajones"])
    assert payload["attributes"]["keycloak_id"] == "22222222-0000-0000-0000-000000000001"


def test_map_user_preserves_existing_attributes() -> None:
    kc_user = {"id": "u1", "username": "x", "attributes": {"dept": ["eng"]}}
    payload = map_user(kc_user)
    assert payload["attributes"]["dept"] == ["eng"]
    assert payload["attributes"]["keycloak_id"] == "u1"
