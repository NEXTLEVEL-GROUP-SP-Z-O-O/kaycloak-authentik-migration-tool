"""Fixture-backed tests for the protocol mapper whitelist translation
(.chief/milestone-1/_contract/03-entity-mapping.md's "Protocol mapper
whitelist" section). tests/fixtures/kc_clients.json's confidential-app now
carries a real Keycloak-generated instance of all six whitelisted types
plus one outside the whitelist (oidc-usermodel-realm-role-mapper),
captured from a live Keycloak 25 via the real admin API -- see task-5b's
verification pass.
"""

import json
from pathlib import Path
from typing import Any

from kc2ak.mappers.protocol_mappers import (
    translate_client_protocol_mappers,
    translate_protocol_mapper,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _confidential_app() -> dict[str, Any]:
    data = json.loads((FIXTURES / "kc_clients.json").read_text())
    return next(c for c in data if c["clientId"] == "confidential-app")


def _mapper(name: str) -> dict[str, Any]:
    mapper = next(m for m in _confidential_app()["protocolMappers"] if m["name"] == name)
    return dict(mapper)


CLIENT_ID = "confidential-app"


# --- the six whitelisted types -----------------------------------------------


def test_usermodel_property_mapper_username() -> None:
    payload, why = translate_protocol_mapper(_mapper("username"), CLIENT_ID)
    assert why is None
    assert payload is not None
    assert payload["expression"] == "return {'preferred_username': user.username}"
    assert payload["scope_name"] == "openid"


def test_usermodel_property_mapper_email() -> None:
    payload, why = translate_protocol_mapper(_mapper("email-attr"), CLIENT_ID)
    assert why is None
    assert payload is not None
    assert payload["expression"] == "return {'email': user.email}"


def test_usermodel_property_mapper_name() -> None:
    kc_mapper = {
        "name": "display-name",
        "protocolMapper": "oidc-usermodel-property-mapper",
        "config": {"user.attribute": "name", "claim.name": "name"},
    }
    payload, why = translate_protocol_mapper(kc_mapper, CLIENT_ID)
    assert why is None
    assert payload is not None
    assert payload["expression"] == "return {'name': user.name}"


def test_usermodel_property_mapper_unsupported_attribute_is_unmapped() -> None:
    # firstName/lastName have no authentik equivalent (authentik has one
    # combined `name` field) -- translating either to user.name would put a
    # full name where only a first or last name was, which is exactly the
    # silent token change this whitelist exists to prevent.
    kc_mapper = {
        "name": "given-name",
        "protocolMapper": "oidc-usermodel-property-mapper",
        "config": {"user.attribute": "firstName", "claim.name": "given_name"},
    }
    payload, why = translate_protocol_mapper(kc_mapper, CLIENT_ID)
    assert payload is None
    assert why is not None
    assert "firstName" in why


def test_usermodel_attribute_mapper() -> None:
    payload, why = translate_protocol_mapper(_mapper("custom-attr"), CLIENT_ID)
    assert why is None
    assert payload is not None
    assert payload["expression"] == "return {'department': user.attributes.get('department')}"


def test_full_name_mapper() -> None:
    # Confirmed against Keycloak's own serverinfo protocolMapperTypes
    # metadata: oidc-full-name-mapper has no claim.name config field at
    # all -- it always targets the literal "name" claim.
    payload, why = translate_protocol_mapper(_mapper("full-name"), CLIENT_ID)
    assert why is None
    assert payload is not None
    assert payload["expression"] == "return {'name': user.name}"


def test_group_membership_mapper() -> None:
    payload, why = translate_protocol_mapper(_mapper("groups"), CLIENT_ID)
    assert why is None
    assert payload is not None
    assert payload["expression"] == "return {'groups': [g.name for g in user.ak_groups.all()]}"


def test_audience_mapper_key_is_literal_aud_not_claim_name() -> None:
    # Confirmed live: Keycloak's oidc-audience-mapper config has no
    # claim.name field at all -- the target claim is always "aud".
    payload, why = translate_protocol_mapper(_mapper("audience"), CLIENT_ID)
    assert why is None
    assert payload is not None
    assert payload["expression"] == "return {'aud': 'confidential-app'}"


def test_hardcoded_claim_mapper() -> None:
    payload, why = translate_protocol_mapper(_mapper("hardcoded"), CLIENT_ID)
    assert why is None
    assert payload is not None
    assert payload["expression"] == "return {'kc2ak_probe': 'probe-value'}"


# --- name derivation / scope_name -------------------------------------------


def test_scope_mapping_name_derives_from_client_id_and_mapper_name() -> None:
    payload, _why = translate_protocol_mapper(_mapper("username"), CLIENT_ID)
    assert payload is not None
    assert payload["name"] == "kc2ak: confidential-app / username"


def test_every_translated_mapping_targets_the_openid_scope() -> None:
    # Confirmed live: a scope mapping only fires when its scope_name is
    # among the scopes actually requested. "openid" is mandatory on every
    # OIDC request, so it's the only choice that reproduces Keycloak's
    # behaviour of a mapper always firing regardless of optional scopes.
    payloads, _unmapped = translate_client_protocol_mappers(_confidential_app(), CLIENT_ID)
    assert payloads
    assert all(p["scope_name"] == "openid" for p in payloads)


# --- outside the whitelist ---------------------------------------------------


def test_realm_role_mapper_is_not_translated() -> None:
    payload, why = translate_protocol_mapper(_mapper("realm-roles"), CLIENT_ID)
    assert payload is None
    assert why == "mapper type not in whitelist"


def test_unknown_mapper_type_is_not_translated() -> None:
    kc_mapper = {
        "name": "cost-centre",
        "protocolMapper": "oidc-script-based-protocol-mapper",
        "config": {},
    }
    payload, why = translate_protocol_mapper(kc_mapper, CLIENT_ID)
    assert payload is None
    assert why == "mapper type not in whitelist"


# --- whole-client translation -------------------------------------------------


def test_translate_client_protocol_mappers_splits_whitelisted_from_unmapped() -> None:
    payloads, unmapped = translate_client_protocol_mappers(_confidential_app(), CLIENT_ID)
    # 7 whitelisted-type instances (email-attr, groups, custom-attr,
    # hardcoded, username, full-name, audience), 1 outside the whitelist
    # (realm-roles).
    assert len(payloads) == 7
    assert len(unmapped) == 1
    assert unmapped[0] == {
        "type": "protocol_mapper",
        "name": "realm-roles",
        "mapper_type": "oidc-usermodel-realm-role-mapper",
        "why": "mapper type not in whitelist",
    }


def test_translate_client_protocol_mappers_empty_for_no_mappers() -> None:
    payloads, unmapped = translate_client_protocol_mappers({}, CLIENT_ID)
    assert payloads == []
    assert unmapped == []


# --- config values never reach the expression unescaped ---------------------


def test_config_value_is_repr_escaped_not_interpolated_raw() -> None:
    # A claim.value containing a quote must not break out of the string
    # literal in the generated expression -- config crosses into code
    # authentik executes.
    kc_mapper = {
        "name": "tricky",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {"claim.name": "note", "claim.value": 'it\'s "quoted"'},
    }
    payload, _why = translate_protocol_mapper(kc_mapper, CLIENT_ID)
    assert payload is not None
    # Must be valid Python and must evaluate to the original string.
    namespace: dict[str, Any] = {}
    exec(f"def f():\n    {payload['expression']}\nresult = f()", namespace)
    assert namespace["result"] == {"note": 'it\'s "quoted"'}
