"""Keycloak identity provider -> Authentik source mapping. Pure: no I/O.

See .chief/milestone-2/_contract/02-idp-mapping.md.
"""

from __future__ import annotations

import textwrap
from typing import Any

from kc2ak.mappers.clients import slugify

IDP_TYPE_UNSUPPORTED = "idp_type_unsupported"
IDP_SECRET_MISSING = "idp_secret_missing"
IDP_FLOW_MISSING = "idp_flow_missing"
IDP_MAPPER = "idp_mapper"
FEDERATED_LINK_SOURCE_MISSING = "federated_link_source_missing"
FEDERATED_LINK_UNWRITABLE = "federated_link_unwritable"

# authentik's public API has no way to create a UserOAuthSourceConnection /
# UserSAMLSourceConnection with a chosen user+source+identifier -- confirmed
# live against authentik 2024.10.5 and unfixed on `main`; see the "Federated
# identity links" amendment in
# .chief/milestone-2/_contract/02-idp-mapping.md. Every created/updated
# source instead gets `user_matching_mode` set so a real login self-links --
# --idp-user-matching selects it, defaulting here to the safest choice.
USER_MATCHING_MODES = ("username_link", "email_link", "identifier")
DEFAULT_USER_MATCHING_MODE = "username_link"

# Keycloak masks clientSecret identically on every route that returns it --
# there is no unmasked endpoint (.chief/milestone-2/_contract/02-idp-mapping.md).
# Treat this literal value as absent, whether it shows up in a Keycloak read
# (it always will) or was pasted into the secrets file by mistake.
MASKED_SECRET = "**********"  # noqa: S105

# Written as consumer_secret when no real secret was supplied. Never a
# working value and never registered for redaction -- it is not secret
# material, just a marker that keeps a disabled source's payload honest about
# why it can't work yet.
PLACEHOLDER_SECRET = "kc2ak-no-secret-supplied"  # noqa: S105

# Provider-type whitelist -- authentik's OAuthSource.provider_type for every
# Keycloak providerId with an exact equivalent. Anything else is CONFLICT /
# idp_type_unsupported: mapping onto generic "openidconnect" would mean
# inventing authorization_url/access_token_url/profile_url, which fails at
# login for real people.
#
# Checked against Keycloak 26.7.1's own /admin/serverinfo provider list and
# authentik 2026.5.6's ProviderTypeEnum. Every provider **stock Keycloak
# offers** that authentik can represent is here: oidc, keycloak-oidc, saml,
# google, github, gitlab, facebook, twitter, microsoft. Nothing is missing --
# Keycloak's remaining stock providers (bitbucket, paypal, stackoverflow,
# openshift-v4, kubernetes, oauth2, jwt-authorization-grant,
# linkedin-openid-connect) have no authentik member at all.
#
# `apple`, `discord`, `okta`, `reddit` and `twitch` are **speculative**: they
# are authentik enum members that stock Keycloak has never offered as a
# providerId, added by reading authentik's side of the table. They can only
# ever match a Keycloak extension, and if one does match, the resulting source
# gets no endpoint URLs. Kept because removing them would change behaviour for
# anyone running such an extension; named here so the next reader does not
# mistake them for verified pairs.
#
# "microsoft" -> "azuread" is the one non-identical pair. The member is
# confirmed present in 2026.5.6's enum, but no live login through a real
# Microsoft provider has ever been performed. authentik 2026.5 also added
# `entraid` as the newer name for the same source; this still writes azuread.
_OAUTH_PROVIDER_TYPES = {
    "oidc": "openidconnect",
    "keycloak-oidc": "openidconnect",
    "google": "google",
    "github": "github",
    "gitlab": "gitlab",
    "facebook": "facebook",
    "twitter": "twitter",
    "okta": "okta",
    "apple": "apple",
    "discord": "discord",
    "reddit": "reddit",
    "twitch": "twitch",
    "microsoft": "azuread",
}

_SAML_PROVIDER_ID = "saml"

# authentik's AuthorizationCodeAuthMethodEnum, read from /api/v3/schema/ on
# 2026.5.6. Keycloak's remaining values (client_secret_jwt, private_key_jwt)
# have no member and are reported by unmapped_idp_fields rather than
# approximated -- how a client authenticates is security-relevant.
_AUTH_CODE_AUTH_METHODS = {
    "client_secret_post": "post_body",
    "client_secret_basic": "basic_auth",
}

# authentik's SAMLNameIDPolicyEnum, same source. Keycloak stores the format as
# the same URN string, so a member passes through unchanged.
_SAML_NAME_ID_POLICIES = frozenset(
    {
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:WindowsDomainQualifiedName",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    }
)


def source_kind(provider_id: str) -> str | None:
    """ "oauth", "saml", or None when the providerId is not in the whitelist
    at all -- the caller's cue to record CONFLICT / idp_type_unsupported
    without creating anything.
    """
    if provider_id in _OAUTH_PROVIDER_TYPES:
        return "oauth"
    if provider_id == _SAML_PROVIDER_ID:
        return "saml"
    return None


def resolved_secret(alias: str, secrets: dict[str, str]) -> str | None:
    """The real secret for this alias from the --idp-secrets file, or None
    when absent -- either missing from the file, or present but equal to
    Keycloak's own masking placeholder (an operator who pasted the masked
    value from Keycloak's admin console has supplied nothing usable, not a
    working secret).
    """
    value = secrets.get(alias)
    if not value or value == MASKED_SECRET:
        return None
    return value


def map_oauth_source(
    kc_idp: dict[str, Any],
    *,
    secret: str | None,
    user_matching_mode: str = DEFAULT_USER_MATCHING_MODE,
    authentication_flow: str | None = None,
    enrollment_flow: str | None = None,
    is_update: bool = False,
) -> dict[str, Any]:
    """Map an OAuth-family Keycloak IdP (oidc/keycloak-oidc or a whitelisted
    social provider) to an authentik OAuthSource create/update payload.
    `secret` is the real value from the secrets file, or None -- a None here
    writes PLACEHOLDER_SECRET **on a create**; see `is_update` below for how
    an update differs.
    URL fields are only set when Keycloak's config has them: a whitelisted
    social provider's config typically doesn't (authentik already knows its
    own endpoints for a known provider_type), while generic "openidconnect"
    requires them -- confirmed live against authentik 2024.10.5, which 400s
    with "authorization_url is required for provider OpenID Connect" when
    they're missing for that provider_type. Leaving them unset rather than
    guessing is correct either way: a genuinely incomplete generic-OIDC
    config is not this tool's to complete, and the write is rejected
    (CONFLICT-free FAILED / api_rejected) rather than silently working with
    invented endpoints. `user_matching_mode` is what stands in for the
    per-user federated links this tool cannot write -- see the "Federated
    identity links" amendment.

    `authentication_flow`/`enrollment_flow` are the CLI-supplied
    --authentication-flow/--enrollment-flow flows' resolved **pks** (or None
    when not supplied). A source needs a real secret **and** both flows to
    work -- missing either one presents a login button that fails mid-flow
    with an error the end user cannot act on, the same reasoning
    .chief/milestone-2/_goal/02-identity-providers.md's opening section
    already applies to the missing-secret case (task-5b amendment to
    .chief/milestone-2/_contract/02-idp-mapping.md: a real login 400s
    "Configured flow does not exist" without them, confirmed live).

    `is_update` changes how an incomplete configuration is written, not
    whether it's incomplete (task-5c amendment): on a create, `enabled` and
    `consumer_secret` are always in the payload -- a source that can't work
    is created disabled, with a placeholder secret, by design. On an update,
    neither key is written when this run cannot supply a real value:
    `enabled` is only ever written `True`, never `False`, and
    `consumer_secret` is omitted entirely rather than sent as
    PLACEHOLDER_SECRET when `secret` is None, so a real secret already
    stored on the live source is never overwritten with a marker that keeps
    it from working. Both leave whatever the live source already had
    untouched. `--update-existing` must never switch off, or silently
    sabotage, an already-working identity provider as a side effect of this
    run's inputs being thinner than a previous run's.
    """
    alias = kc_idp["alias"]
    config = kc_idp.get("config") or {}
    enabled = secret is not None and authentication_flow is not None and enrollment_flow is not None
    payload: dict[str, Any] = {
        "name": alias,
        "slug": slugify(alias),
        "provider_type": _OAUTH_PROVIDER_TYPES[kc_idp["providerId"]],
        "consumer_key": config.get("clientId", ""),
        "user_matching_mode": user_matching_mode,
    }
    if secret is not None or not is_update:
        payload["consumer_secret"] = secret if secret is not None else PLACEHOLDER_SECRET
    if enabled or not is_update:
        payload["enabled"] = enabled
    if config.get("authorizationUrl"):
        payload["authorization_url"] = config["authorizationUrl"]
    if config.get("tokenUrl"):
        payload["access_token_url"] = config["tokenUrl"]
    if config.get("userInfoUrl"):
        payload["profile_url"] = config["userInfoUrl"]
    if config.get("issuer"):
        payload["oidc_well_known_url"] = config["issuer"]
    if authentication_flow is not None:
        payload["authentication_flow"] = authentication_flow
    if enrollment_flow is not None:
        payload["enrollment_flow"] = enrollment_flow
    auth_method = _AUTH_CODE_AUTH_METHODS.get(config.get("clientAuthMethod", ""))
    if auth_method is not None:
        payload["authorization_code_auth_method"] = auth_method
    return payload


def unmapped_idp_fields(kc_idp: dict[str, Any]) -> list[dict[str, str]]:
    """Config values with no faithful target on the authentik side. Only
    recorded when the source actually carries one -- an absent field is not
    a loss (mappers/clients.py's unmapped_client_fields makes the same call).
    """
    config = kc_idp.get("config") or {}
    entries: list[dict[str, str]] = []

    # authentik's AuthorizationCodeAuthMethodEnum has only basic_auth and
    # post_body. Keycloak's JWT-based client authentication (client_secret_jwt,
    # private_key_jwt) has no member, and picking the nearest one would change
    # how the source authenticates to the provider -- a security-relevant
    # substitution, so it is reported instead.
    method = config.get("clientAuthMethod")
    if method and method not in _AUTH_CODE_AUTH_METHODS:
        entries.append(
            {
                "type": "idp_field",
                "name": "clientAuthMethod",
                "why": f"no authentik equivalent for {method}",
            }
        )

    # SAMLNameIDPolicyEnum covers the six standard formats; a Keycloak realm
    # can carry a non-standard one, which authentik would reject outright.
    name_id = config.get("nameIDPolicyFormat")
    if name_id and name_id not in _SAML_NAME_ID_POLICIES:
        entries.append(
            {
                "type": "idp_field",
                "name": "nameIDPolicyFormat",
                "why": f"not a SAML name ID policy authentik accepts: {name_id}",
            }
        )

    return entries


def pem_certificate(der_base64: str) -> str:
    """Keycloak stores `signingCertificate` as bare base64 DER, no PEM
    envelope -- confirmed live against Keycloak 25.0.6's identity-provider
    read. authentik's CertificateKeyPairRequest.certificate_data expects a
    full PEM document (confirmed live against authentik 2024.10.5: a bare
    base64 blob without the envelope is rejected).
    """
    body = "\n".join(textwrap.wrap(der_base64.strip(), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def map_saml_source(
    kc_idp: dict[str, Any],
    *,
    pre_authentication_flow: str,
    signing_kp: str | None,
    user_matching_mode: str = DEFAULT_USER_MATCHING_MODE,
    authentication_flow: str | None = None,
    enrollment_flow: str | None = None,
    is_update: bool = False,
) -> dict[str, Any]:
    """Map a `saml` Keycloak IdP to an authentik SAMLSource create/update
    payload. `pre_authentication_flow` is the flow's resolved pk, not its
    slug -- confirmed live that SAMLSourceRequest, like OAuth2Provider's own
    flow fields, rejects a slug with "not a valid UUID". `signing_kp` is the
    pk of the CertificateKeyPair imported from Keycloak's signingCertificate,
    or None when Keycloak's config has none (SAMLSourceRequest does not
    require it). `user_matching_mode` is what stands in for the per-user
    federated links this tool cannot write -- see the "Federated identity
    links" amendment.

    `authentication_flow`/`enrollment_flow` (task-5c): the identical base
    `Source` fields OAuth sources needed to not be login-inert
    (task-5b) -- `pre_authentication_flow` is a different, SAML-specific
    stage flow and its presence does not imply these two are set.
    SAMLSourceRequest needs no secret, so `enabled` here depends only on
    both being supplied. `is_update` behaves exactly as in
    `map_oauth_source`: on a create, `enabled` is always written, `True` or
    `False`; on an update, it is only ever written `True`, and omitted
    entirely (not sent as `False`) when this run can't fully configure the
    source, so an update never disables an already-working one.
    """
    alias = kc_idp["alias"]
    config = kc_idp.get("config") or {}
    enabled = authentication_flow is not None and enrollment_flow is not None
    payload: dict[str, Any] = {
        "name": alias,
        "slug": slugify(alias),
        "sso_url": config.get("singleSignOnServiceUrl", ""),
        "pre_authentication_flow": pre_authentication_flow,
        "user_matching_mode": user_matching_mode,
    }
    if enabled or not is_update:
        payload["enabled"] = enabled
    if config.get("singleLogoutServiceUrl"):
        payload["slo_url"] = config["singleLogoutServiceUrl"]
    if config.get("idpEntityId"):
        payload["issuer"] = config["idpEntityId"]
    if signing_kp is not None:
        payload["signing_kp"] = signing_kp
    if authentication_flow is not None:
        payload["authentication_flow"] = authentication_flow
    if enrollment_flow is not None:
        payload["enrollment_flow"] = enrollment_flow
    # Keycloak stores the format as the same URN authentik's enum uses, so a
    # recognised value passes through untouched. Anything else is left to
    # authentik's own default and reported by unmapped_idp_fields -- sending
    # an unrecognised URN would be rejected outright.
    if config.get("nameIDPolicyFormat") in _SAML_NAME_ID_POLICIES:
        payload["name_id_policy"] = config["nameIDPolicyFormat"]
    return payload


def unmapped_idp_mappers(kc_mappers: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Every Keycloak IdP mapper is reported, never translated --
    .chief/milestone-2/_contract/02-idp-mapping.md's "Keycloak IdP mappers
    read and reported as unmapped type idp_mapper; not translated."
    """
    return [
        {"type": IDP_MAPPER, "name": m["name"], "why": "IdP mappers are not translated"}
        for m in kc_mappers
    ]
