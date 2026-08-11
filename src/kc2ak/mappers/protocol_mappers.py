"""Keycloak protocolMapper -> Authentik ScopeMapping translation, per the
six-type whitelist in .chief/milestone-1/_contract/03-entity-mapping.md.
Pure: no I/O.

Anything outside the whitelist -- including a whitelisted mapper *type*
whose config uses a value this tool has no faithful translation for -- is
not translated. It is reported in `unmapped`, never guessed at
(.chief/milestone-1/_goal/02-safety-and-blast-radius.md: "Nothing is
guessed"). Under-translating is safe and visible; over-translating is
silent and dangerous.

Three decisions made from live findings against a real Keycloak 25 /
authentik 2024.10.5 (see task-5b's verification pass), not from the
contract text alone:

- `oidc-audience-mapper`'s Keycloak config has no `claim.name` field at
  all (confirmed live, and against Keycloak's own `GET /admin/serverinfo`
  protocolMapperTypes metadata) -- the contract's per-row "static `aud`"
  wording is correct and the blanket "config[\"claim.name\"] becomes the
  dict key in every case" sentence is the exception-less summary that
  doesn't hold for this one row. The dict key for this mapper is the
  literal string "aud".
- `oidc-full-name-mapper` has no `claim.name` field either -- confirmed the
  same way. Keycloak's own description of the built-in mapper ("Maps the
  user's first and last name to the OpenID Connect 'name' claim") says the
  target claim is always literally "name", not configurable. This is a
  second exception to the same blanket sentence, not a special case
  invented here.
- `scope_name`: the contract specifies ScopeMapping's four fields but not
  what scope to attach a translated claim to. Authentik only runs a scope
  mapping's expression when the client's token request actually includes
  that scope (confirmed live via authentik's OpenAPI schema:
  "Scope name requested by the client"). `openid` is the one scope every
  OIDC request is required to include, so it is the only choice that
  reproduces the Keycloak behaviour being translated -- a Keycloak
  protocol mapper always fires, regardless of what optional scopes a
  client happens to request. Confirmed live: a scope mapping with
  `scope_name="openid"` fired in an id_token issued for a bare
  `scope=openid` request, while a same-run `scope_name="profile"` mapping
  did not fire until `profile` was actually requested. Also confirmed
  live: two ScopeMappings sharing a `scope_name` both fire and their
  claims merge without collision, so this is safe even alongside
  authentik's own default mappings.

The `oidc-audience-mapper` translation is not inert: confirmed live with a
mapping returning an `aud` value *different* from the client's own
`client_id` (the realistic case -- a Keycloak audience mapper pointing at a
separate backend API) that the mapping's value replaces authentik's
standard `aud` claim in the issued id_token, rather than being ignored or
merged alongside it. This matters because the whitelisted fixture example
happens to set `included.client.audience` equal to the client's own
`client_id`, which would have looked identical whether or not the mapping
fired at all.

Not carried over by this module, and not currently attached by
migrate_clients either: authentik's own default OAuth scope mappings
(the ones behind `openid`/`profile`/`email` in a hand-created provider,
e.g. `preferred_username`/`name`/`email`/`groups`). Confirmed live that
creating an OAuth2Provider via the API does not auto-attach them --
`property_mappings` is exactly what the caller passes, nothing more.
mappers/clients.py's `unmapped_client_fields` treats a Keycloak
`defaultClientScopes` entry matching authentik's default scope names
(`_AUTHENTIK_DEFAULT_SCOPES`) as not lost data, on the premise that
authentik's equivalent is already present -- true for realm scope-level
claims in Keycloak (which this tool doesn't read at all, out of scope
everywhere), but for a client whose `preferred_username`/`email`/`name`
claims came from Keycloak's *realm default client scopes* rather than
client-level protocol mappers, nothing in this tool's read set or its
`unmapped` reporting captures that gap -- a migrated provider can silently
lose those claims with nothing in the report to say so. This is a
milestone-level design question (whether migrate_clients should also
attach authentik's own default mappings), not something this module
decides on its own; flagged for the chief, not resolved here.
"""

from __future__ import annotations

from typing import Any

# Authentik's User model has .username, .email, and .name (one combined
# display-name field, no separate first/last -- see
# _contract/03-entity-mapping.md's Users table). Only these three
# config["user.attribute"] values have a faithful authentik equivalent;
# Keycloak's "firstName"/"lastName" property mappers do not, since half a
# name is not the same claim as the full name.
_USER_ATTRIBUTE_TO_EXPR = {
    "username": "user.username",
    "email": "user.email",
    "name": "user.name",
}

# Every translated claim is attached to this scope -- see module docstring.
_SCOPE_NAME = "openid"

_WHITELISTED_TYPES = frozenset(
    {
        "oidc-usermodel-property-mapper",
        "oidc-usermodel-attribute-mapper",
        "oidc-full-name-mapper",
        "oidc-group-membership-mapper",
        "oidc-audience-mapper",
        "oidc-hardcoded-claim-mapper",
    }
)


def _return_dict_expression(claim_name: str, value_code: str) -> str:
    """`value_code` is Python source (an expression or a pre-repr'd
    literal), not a value -- callers pass either a `user.…` expression or
    `repr(some_config_value)`, never an unescaped config value, since a
    config value crosses into code authentik executes.
    """
    return f"return {{{claim_name!r}: {value_code}}}"


def _scope_mapping_payload(
    client_id: str, kc_mapper: dict[str, Any], expression: str
) -> dict[str, Any]:
    return {
        "name": f"kc2ak: {client_id} / {kc_mapper['name']}",
        "scope_name": _SCOPE_NAME,
        "description": "",
        "expression": expression,
    }


def translate_protocol_mapper(
    kc_mapper: dict[str, Any], client_id: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Translate one Keycloak protocolMapper to an authentik ScopeMapping
    create payload. Returns (payload, None) when translatable, or
    (None, why) when not -- `why` is always populated, never left for the
    caller to infer.
    """
    mapper_type = kc_mapper.get("protocolMapper")
    config: dict[str, Any] = kc_mapper.get("config") or {}
    claim_name = config.get("claim.name")

    if mapper_type == "oidc-usermodel-property-mapper":
        attr = config.get("user.attribute")
        value_expr = _USER_ATTRIBUTE_TO_EXPR.get(attr) if isinstance(attr, str) else None
        if value_expr is None:
            return None, f"user.attribute {attr!r} has no authentik equivalent"
        if not claim_name:
            return None, "claim.name missing"
        expr = _return_dict_expression(claim_name, value_expr)
        return _scope_mapping_payload(client_id, kc_mapper, expr), None

    if mapper_type == "oidc-usermodel-attribute-mapper":
        attr = config.get("user.attribute")
        if not attr:
            return None, "user.attribute missing"
        if not claim_name:
            return None, "claim.name missing"
        expr = _return_dict_expression(claim_name, f"user.attributes.get({attr!r})")
        return _scope_mapping_payload(client_id, kc_mapper, expr), None

    if mapper_type == "oidc-full-name-mapper":
        # "name" is a literal claim key, not config["claim.name"] -- this
        # mapper has no such config field (confirmed live). See module
        # docstring.
        expr = _return_dict_expression("name", "user.name")
        return _scope_mapping_payload(client_id, kc_mapper, expr), None

    if mapper_type == "oidc-group-membership-mapper":
        if not claim_name:
            return None, "claim.name missing"
        expr = _return_dict_expression(claim_name, "[g.name for g in user.ak_groups.all()]")
        return _scope_mapping_payload(client_id, kc_mapper, expr), None

    if mapper_type == "oidc-audience-mapper":
        audience = config.get("included.client.audience")
        if not audience:
            return None, "included.client.audience missing"
        # "aud" is a literal claim key, not config["claim.name"] -- see
        # module docstring.
        expr = _return_dict_expression("aud", repr(audience))
        return _scope_mapping_payload(client_id, kc_mapper, expr), None

    if mapper_type == "oidc-hardcoded-claim-mapper":
        value = config.get("claim.value")
        if value is None:
            return None, "claim.value missing"
        if not claim_name:
            return None, "claim.name missing"
        expr = _return_dict_expression(claim_name, repr(value))
        return _scope_mapping_payload(client_id, kc_mapper, expr), None

    return None, "mapper type not in whitelist"


def translate_client_protocol_mappers(
    kc_client: dict[str, Any], client_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Translate every protocol mapper on one Keycloak client. Returns
    (scope_mapping_payloads, unmapped_entries) -- callers create the
    ScopeMapping objects and attach them; this module never touches the
    network.

    Reads `kc_client["protocolMappers"]`, the array Keycloak's
    `GET /clients` already embeds per client -- confirmed live identical
    (for the config fields this module reads) to the contract's dedicated
    `GET .../protocol-mappers/models` endpoint, so no second HTTP call is
    made for data already in hand.
    """
    payloads: list[dict[str, Any]] = []
    unmapped: list[dict[str, str]] = []
    for kc_mapper in kc_client.get("protocolMappers") or []:
        payload, why = translate_protocol_mapper(kc_mapper, client_id)
        if payload is not None:
            payloads.append(payload)
        else:
            unmapped.append(
                {
                    "type": "protocol_mapper",
                    "name": kc_mapper.get("name", ""),
                    "mapper_type": kc_mapper.get("protocolMapper", ""),
                    "why": why or "not translatable",
                }
            )
    return payloads, unmapped
