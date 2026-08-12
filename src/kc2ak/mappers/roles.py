"""Keycloak realm role -> Authentik group mapping. Pure: no I/O.

See .chief/milestone-2/_contract/01-role-mapping.md.
"""

from __future__ import annotations

from typing import Any

COMPOSITE_ROLE_UNSUPPORTED = "composite_role_unsupported"
ROLE_NAME_TAKEN_BY_GROUP = "role_name_taken_by_group"
ROLE_ASSIGNMENT_ROLE_MISSING = "role_assignment_role_missing"

# What map_role() stamps onto every migrated role's Group.attributes, so a
# re-run can tell a migrated role apart from a pre-existing group of the same
# name -- without it the two would be indistinguishable and a re-run could
# silently merge them (.chief/milestone-2/_contract/01-role-mapping.md).
KC2AK_ORIGIN_REALM_ROLE = "realm_role"

# Present on every realm regardless of custom roles; excluding them by name
# is what .chief/milestone-2/_goal/01-roles-scope.md requires -- counting
# default-roles-{realm} (itself composite on every realm) would report a
# CONFLICT on every single run, forbidden by
# .chief/_rules/_standard/diagnostics.md.
_BUILTIN_ROLE_NAMES = frozenset({"offline_access", "uma_authorization"})


def builtin_role_names(realm: str) -> frozenset[str]:
    """Every name excluded before the read is counted: the two Keycloak
    seeds identically on every realm, plus that realm's own
    default-roles-{realm}.
    """
    return _BUILTIN_ROLE_NAMES | {f"default-roles-{realm}"}


def is_composite(kc_role: dict[str, Any]) -> bool:
    """True when the role must be refused as CONFLICT /
    composite_role_unsupported -- GET /roles already returns this flag, so
    detecting it never requires reading the composite's contents
    (.chief/milestone-2/_contract/01-role-mapping.md's "Endpoints read").
    """
    return bool(kc_role.get("composite", False))


def map_role(kc_role: dict[str, Any]) -> dict[str, Any]:
    """Map a flat, non-composite realm role to an Authentik group create/update
    payload. Caller must check is_composite() first -- a composite role is a
    CONFLICT, not something this function knows how to represent.
    """
    attributes = dict(kc_role.get("attributes") or {})
    attributes["keycloak_id"] = kc_role["id"]
    attributes["kc2ak_origin"] = KC2AK_ORIGIN_REALM_ROLE
    return {"name": kc_role["name"], "attributes": attributes}


def is_role_origin(ak_group: dict[str, Any]) -> bool:
    """True if an existing Authentik group was itself created from a
    migrated realm role. This is what makes a same-named pre-existing group
    a CONFLICT rather than a match on re-run --
    .chief/milestone-2/_contract/01-role-mapping.md's "Why a same-named group
    is a conflict, not a match".
    """
    return (ak_group.get("attributes") or {}).get("kc2ak_origin") == KC2AK_ORIGIN_REALM_ROLE


def unmapped_role_fields(kc_role: dict[str, Any]) -> list[dict[str, str]]:
    """`description` has no equivalent field on Authentik's Group -- recorded
    only when the role actually has one, same "don't report unconditionally"
    discipline as mappers.clients.unmapped_client_fields.
    """
    if kc_role.get("description"):
        return [{"type": "role_field", "name": "description", "why": "not carried over"}]
    return []


def unmapped_client_roles(kc_client_roles: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Every client role is reported, never migrated --
    .chief/milestone-2/_goal/01-roles-scope.md's "Client roles are not
    migrated": Keycloak namespaces them per client, so flattening two
    same-named client roles from different clients into one Authentik group
    would merge two distinct identities.
    """
    return [
        {"type": "client_role", "name": role["name"], "why": "client roles are not migrated"}
        for role in kc_client_roles
    ]
