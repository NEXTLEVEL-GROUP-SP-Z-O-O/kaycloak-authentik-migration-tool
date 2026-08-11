"""Keycloak user -> Authentik user mapping. Pure: no I/O.

See .chief/milestone-1/_contract/03-entity-mapping.md.
"""

from __future__ import annotations

from typing import Any


def map_user(kc_user: dict[str, Any]) -> dict[str, Any]:
    """Map a Keycloak user to an Authentik user create payload."""
    name = " ".join(p for p in (kc_user.get("firstName"), kc_user.get("lastName")) if p)
    attributes = dict(kc_user.get("attributes") or {})
    attributes["keycloak_id"] = kc_user["id"]
    return {
        "username": kc_user["username"],
        "email": kc_user.get("email") or "",
        "name": name,
        "is_active": kc_user.get("enabled", True),
        "attributes": attributes,
    }
