"""Keycloak identity provider -> Authentik source mapping. Pure: no I/O.

See .chief/milestone-2/_contract/02-idp-mapping.md.
"""

from __future__ import annotations

import textwrap
from typing import Any

from kc2ak.mappers.clients import slugify

IDP_TYPE_UNSUPPORTED = "idp_type_unsupported"
IDP_SECRET_MISSING = "idp_secret_missing"
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
# login for real people. "microsoft" -> "azuread" is the one non-identical
# pair and, per the contract, still needs live confirmation beyond this
# milestone's seed (it has no Microsoft IdP case).
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
) -> dict[str, Any]:
    """Map an OAuth-family Keycloak IdP (oidc/keycloak-oidc or a whitelisted
    social provider) to an authentik OAuthSource create/update payload.
    `secret` is the real value from the secrets file, or None -- a None here
    writes PLACEHOLDER_SECRET and `enabled: false`
    (.chief/milestone-2/_contract/02-idp-mapping.md's enabled/disabled rule).
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
    """
    alias = kc_idp["alias"]
    config = kc_idp.get("config") or {}
    payload: dict[str, Any] = {
        "name": alias,
        "slug": slugify(alias),
        "provider_type": _OAUTH_PROVIDER_TYPES[kc_idp["providerId"]],
        "consumer_key": config.get("clientId", ""),
        "consumer_secret": secret if secret is not None else PLACEHOLDER_SECRET,
        "enabled": secret is not None,
        "user_matching_mode": user_matching_mode,
    }
    if config.get("authorizationUrl"):
        payload["authorization_url"] = config["authorizationUrl"]
    if config.get("tokenUrl"):
        payload["access_token_url"] = config["tokenUrl"]
    if config.get("userInfoUrl"):
        payload["profile_url"] = config["userInfoUrl"]
    if config.get("issuer"):
        payload["oidc_well_known_url"] = config["issuer"]
    return payload


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
    """
    alias = kc_idp["alias"]
    config = kc_idp.get("config") or {}
    payload: dict[str, Any] = {
        "name": alias,
        "slug": slugify(alias),
        "sso_url": config.get("singleSignOnServiceUrl", ""),
        "pre_authentication_flow": pre_authentication_flow,
        # SAMLSourceRequest requires no secret -- unaffected by the
        # unobtainable-clientSecret problem, so always created working.
        "enabled": True,
        "user_matching_mode": user_matching_mode,
    }
    if config.get("singleLogoutServiceUrl"):
        payload["slo_url"] = config["singleLogoutServiceUrl"]
    if config.get("idpEntityId"):
        payload["issuer"] = config["idpEntityId"]
    if signing_kp is not None:
        payload["signing_kp"] = signing_kp
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
