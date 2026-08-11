"""Keycloak group -> Authentik group mapping. Pure: no I/O.

See .chief/milestone-1/_contract/03-entity-mapping.md.
"""

from __future__ import annotations

from typing import Any

NESTED_GROUPS_UNSUPPORTED = "nested_groups_unsupported"


def is_nested(kc_group: dict[str, Any]) -> bool:
    """True if this group has subgroups and must be reported as a conflict
    rather than migrated.

    Keycloak 25's admin API list endpoint never populates `subGroups` (even
    with `populateHierarchy=true`) -- nesting is only visible via
    `subGroupCount`, confirmed against a live instance. Both fields are
    checked so fixtures built from either the realm-export shape
    (`subGroups`) or the live list endpoint (`subGroupCount`) are handled
    the same way.
    """
    return bool(kc_group.get("subGroups")) or kc_group.get("subGroupCount", 0) > 0


def map_group(kc_group: dict[str, Any]) -> dict[str, Any]:
    """Map a flat Keycloak group to an Authentik group create payload.

    Caller must check is_nested() first -- nested groups are a conflict,
    not something this function knows how to represent.
    """
    attributes = dict(kc_group.get("attributes") or {})
    attributes["keycloak_id"] = kc_group["id"]
    return {"name": kc_group["name"], "attributes": attributes}
