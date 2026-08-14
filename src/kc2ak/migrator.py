"""Read -> map -> diff -> write orchestration for groups, users, memberships,
clients, and (milestone-2) realm roles, role assignments, identity providers
and federated links.

Dry-run is the default: writes only happen when apply=True. Every write path
is behind that flag, per
.chief/milestone-1/_goal/02-safety-and-blast-radius.md. Every migrate_* here
produces EntityResult records; cli.py owns the --only scope, the fixed
processing order and the counts blocks that consume them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from kc2ak.authentik_client import AuthentikClient
from kc2ak.keycloak_client import KeycloakClient
from kc2ak.mappers.clients import (
    is_migratable_client,
    map_application,
    map_provider,
    slugify,
    standard_scope_mappings,
    unmapped_client_fields,
)
from kc2ak.mappers.groups import NESTED_GROUPS_UNSUPPORTED, is_nested, map_group
from kc2ak.mappers.idps import (
    DEFAULT_USER_MATCHING_MODE,
    FEDERATED_LINK_SOURCE_MISSING,
    FEDERATED_LINK_UNWRITABLE,
    IDP_FLOW_MISSING,
    IDP_SECRET_MISSING,
    IDP_TYPE_UNSUPPORTED,
    map_oauth_source,
    map_saml_source,
    pem_certificate,
    resolved_secret,
    source_kind,
    unmapped_idp_mappers,
)
from kc2ak.mappers.protocol_mappers import translate_client_protocol_mappers
from kc2ak.mappers.roles import (
    COMPOSITE_ROLE_UNSUPPORTED,
    ROLE_ASSIGNMENT_ROLE_MISSING,
    ROLE_NAME_TAKEN_BY_GROUP,
    builtin_role_names,
    is_composite,
    is_role_origin,
    map_role,
    unmapped_client_roles,
    unmapped_role_fields,
)
from kc2ak.mappers.users import map_user

CREATED = "CREATED"
SKIPPED = "SKIPPED"
UPDATED = "UPDATED"
CONFLICT = "CONFLICT"
FAILED = "FAILED"

USERNAME_TAKEN_EMAIL_DIFFERS = "username_taken_email_differs"
EMAIL_DUPLICATE_USERNAME_NEW = "email_duplicate_username_new"
API_REJECTED = "api_rejected"


@dataclass
class EntityResult:
    """One row of the eventual report (.chief/milestone-1/_contract/02-report-schema.md).
    Held in memory here; task-3 serialises it.
    """

    kind: str
    keycloak_id: str
    keycloak_ref: str
    authentik_ref: str | int | None
    outcome: str
    reason: str | None = None
    unmapped: list[dict[str, str]] = field(default_factory=list)
    # Not part of the report schema -- internal-only, used by task-3's
    # recovery-mail counting (a CREATED user's eligibility depends on
    # whether they have an email and are active). The report serializer
    # projects only the schema fields, so these never leak into the JSON.
    email: str = ""
    is_active: bool = True


def _saml_signing_kp(ak: AuthentikClient, kc_idp: dict[str, Any]) -> str | None:
    """Find-or-create the CertificateKeyPair for a SAML IdP's signing
    certificate, mirroring migrate_clients' find_scope_mapping_by_name
    pattern so a re-run imports the certificate once rather than
    accumulating a new keypair every migrate. Only called from an apply
    branch -- creating a keypair is a write, and importing it speculatively
    on a dry run or a matched (SKIPPED) source would violate
    .chief/milestone-1/_goal/02-safety-and-blast-radius.md. Returns None
    when Keycloak's config has no certificate; SAMLSourceRequest does not
    require one.
    """
    cert = (kc_idp.get("config") or {}).get("signingCertificate")
    if not cert:
        return None
    name = f"kc2ak: {kc_idp['alias']} signing certificate"
    existing = ak.find_certificate_keypair_by_name(name)
    if existing is not None:
        return str(existing["pk"])
    response = ak.create_certificate_keypair(
        {"name": name, "certificate_data": pem_certificate(cert)}
    )
    response.raise_for_status()
    return str(response.json()["pk"])


def migrate_idps(
    kc: KeycloakClient,
    ak: AuthentikClient,
    realm: str,
    *,
    apply: bool,
    update_existing: bool = False,
    secrets: dict[str, str] | None = None,
    pre_authentication_flow: str | None = None,
    user_matching_mode: str = DEFAULT_USER_MATCHING_MODE,
    authentication_flow: str | None = None,
    enrollment_flow: str | None = None,
) -> list[EntityResult]:
    """One entity per Keycloak identity provider, matched against an
    authentik source by natural key (source `slug` <- IdP `alias`,
    type-agnostic via AuthentikClient.find_source_by_slug). A providerId
    outside the whitelist (mappers.idps.source_kind) is CONFLICT /
    idp_type_unsupported and writes nothing -- mapping an unrecognised
    social provider onto generic openidconnect would mean inventing
    endpoint URLs (.chief/milestone-2/_contract/02-idp-mapping.md). Also
    recorded in `unmapped` with the raw providerId, since the CONFLICT
    reason slug alone does not surface it anywhere in the report (decision
    recorded in .chief/milestone-2/_contract/03-cli-and-report-extensions.md's
    amendment).

    An OAuth-family source is created (or, under --update-existing, updated)
    `enabled` only when `secrets` has a real value for that alias
    (mappers.idps.resolved_secret); otherwise it is written disabled with a
    placeholder secret and an `unmapped` entry of type idp_secret_missing --
    computed the same on a dry run as an applied one, so the CLI's "N
    identity providers created disabled" line is accurate before --apply,
    not just after. Never attached to a SKIPPED match: nothing was written
    there, so tagging an already-enabled, already-working source as
    "disabled" would be a false alarm an operator can't act on
    (.chief/_rules/_standard/diagnostics.md). A SAML source never has the
    secret problem (SAMLSourceRequest needs no secret), but is otherwise
    gated by `authentication_flow`/`enrollment_flow` exactly like an OAuth
    source -- see below (task-5c amendment).
    `pre_authentication_flow` is the CLI-supplied **slug**; preconditions
    already confirmed it resolves before this ever runs *when a SAML IdP is
    present*, but SAMLSourceRequest itself rejects a slug outright (confirmed
    live -- same "not a valid UUID" behaviour as OAuth2Provider's flow
    fields), so it is resolved to a pk lazily, at most once, only when a SAML
    IdP is actually about to be written -- an unused/bogus flag on a realm
    with no SAML IdP must stay harmless, since preconditions never validated
    it in that case. Keycloak IdP mappers are read once per provider and
    reported as unmapped type idp_mapper, unconditionally, same as
    migrate_clients' client-role read.

    `user_matching_mode` is written onto every created/updated source
    (mappers.idps.map_oauth_source/map_saml_source) -- it stands in for the
    per-user federated links this tool cannot write at all: authentik's
    public API has no way to create a UserOAuthSourceConnection /
    UserSAMLSourceConnection with a chosen user+source+identifier, confirmed
    live against authentik 2024.10.5 and unfixed on `main`. See the
    "Federated identity links" amendment in
    .chief/milestone-2/_contract/02-idp-mapping.md. migrate_federated_links
    reports, per source, how many Keycloak users depend on this matching
    mode working instead of writing anything.

    `authentication_flow`/`enrollment_flow` are the CLI-supplied **slugs**
    for --authentication-flow/--enrollment-flow, optional unlike
    `pre_authentication_flow`: neither OAuthSourceRequest nor
    SAMLSourceRequest requires them, so a source of either kind can be
    created without them -- a missing one means the source is written
    disabled with an idp_flow_missing unmapped entry, not a precondition
    failure (.chief/milestone-2/_contract/02-idp-mapping.md's task-5b
    amendment, widened to SAML in task-5c: `pre_authentication_flow` is a
    different, SAML-specific stage flow -- its presence never implied these
    two were set, so a migrated SAML source was shipped `enabled: true`
    unconditionally until this task).

    On `--update-existing`, `enabled` is never written `false`, and an
    OAuth source's `consumer_secret` is never overwritten with a placeholder
    (task-5c, the latter caught alongside the former: the same "this run's
    inputs are thinner than a previous run's" bug, in the same field-omission
    shape): a matched source this run can't fully configure (`is_update=True`
    passed to mappers.idps.map_oauth_source/map_saml_source) keeps whatever
    its live `enabled`/`consumer_secret` already were, reported via the same
    idp_flow_missing (or idp_secret_missing) unmapped entry a create would
    get, rather than being switched off or silently sabotaged.
    """
    results: list[EntityResult] = []
    secrets = secrets or {}
    # Resolved lazily, at most once per run, only when a SAML IdP is
    # actually about to be written -- not eagerly at the top. A bogus
    # --pre-authentication-flow with no SAML IdP in scope must stay harmless
    # (preconditions only validate the flag when one is present), so calling
    # AuthentikClient.get_flow_pk unconditionally here would 500 on
    # `results[0]` for a flow that was never going to be used.
    pre_auth_flow_pk_cache: list[str] = []

    def _pre_auth_flow_pk() -> str:
        assert pre_authentication_flow is not None
        if not pre_auth_flow_pk_cache:
            pre_auth_flow_pk_cache.append(ak.get_flow_pk(pre_authentication_flow))
        return pre_auth_flow_pk_cache[0]

    # Same lazy-resolve-once pattern, but each is only ever resolved if the
    # operator actually supplied it -- neither flag requires an OAuth IdP to
    # be present, so an unsupplied one must stay `None` all the way through
    # rather than triggering a resolution that was never asked for.
    auth_flow_pk_cache: list[str] = []
    enrollment_flow_pk_cache: list[str] = []

    def _auth_flow_pk() -> str | None:
        if authentication_flow is None:
            return None
        if not auth_flow_pk_cache:
            auth_flow_pk_cache.append(ak.get_flow_pk(authentication_flow))
        return auth_flow_pk_cache[0]

    def _enrollment_flow_pk() -> str | None:
        if enrollment_flow is None:
            return None
        if not enrollment_flow_pk_cache:
            enrollment_flow_pk_cache.append(ak.get_flow_pk(enrollment_flow))
        return enrollment_flow_pk_cache[0]

    for kc_idp in kc.get_identity_providers(realm):
        alias = kc_idp["alias"]
        provider_id = kc_idp["providerId"]
        kc_id = kc_idp.get("internalId") or alias
        unmapped = unmapped_idp_mappers(kc.get_idp_mappers(realm, alias))
        kind = source_kind(provider_id)

        if kind is None:
            unmapped.append(
                {
                    "type": IDP_TYPE_UNSUPPORTED,
                    "name": provider_id,
                    "why": "no authentik source equivalent",
                }
            )
            results.append(
                EntityResult("idp", kc_id, alias, None, CONFLICT, IDP_TYPE_UNSUPPORTED, unmapped)
            )
            continue

        secret = resolved_secret(alias, secrets) if kind == "oauth" else None
        # Only meaningful on a branch that actually writes (or would write)
        # the source: a SKIPPED match touches nothing, so tagging it would
        # tell an operator their already-enabled, already-working source is
        # "created disabled" -- wrong, and exactly the kind of noise that
        # teaches operators to ignore `unmapped` (.chief/_rules/_standard/diagnostics.md).
        # Computed from the flags themselves, not from a resolved pk -- this
        # must be identical on a dry run and an applied one (same fidelity
        # rule as idp_secret_missing), and dry-run branches below never
        # resolve a flow slug to a pk at all.
        missing_flows = [
            name
            for name, value in (
                ("authentication_flow", authentication_flow),
                ("enrollment_flow", enrollment_flow),
            )
            if value is None
        ]
        write_unmapped = (
            unmapped
            + (
                [{"type": IDP_SECRET_MISSING, "name": alias, "why": "no secret supplied"}]
                if kind == "oauth" and secret is None
                else []
            )
            + (
                [
                    {
                        "type": IDP_FLOW_MISSING,
                        "name": alias,
                        "why": f"{' and '.join(missing_flows)} not supplied",
                    }
                ]
                if missing_flows
                else []
            )
        )

        try:
            existing = ak.find_source_by_slug(slugify(alias))

            if existing is not None:
                if not update_existing:
                    results.append(
                        EntityResult(
                            "idp", kc_id, alias, existing["pk"], SKIPPED, unmapped=unmapped
                        )
                    )
                    continue
                if not apply:
                    results.append(
                        EntityResult(
                            "idp", kc_id, alias, existing["pk"], UPDATED, unmapped=write_unmapped
                        )
                    )
                    continue
                if kind == "oauth":
                    payload = map_oauth_source(
                        kc_idp,
                        secret=secret,
                        user_matching_mode=user_matching_mode,
                        authentication_flow=_auth_flow_pk(),
                        enrollment_flow=_enrollment_flow_pk(),
                        is_update=True,
                    )
                    update_response = ak.update_oauth_source(payload["slug"], payload)
                else:
                    pre_auth_flow_pk = _pre_auth_flow_pk()
                    payload = map_saml_source(
                        kc_idp,
                        pre_authentication_flow=pre_auth_flow_pk,
                        signing_kp=_saml_signing_kp(ak, kc_idp),
                        user_matching_mode=user_matching_mode,
                        authentication_flow=_auth_flow_pk(),
                        enrollment_flow=_enrollment_flow_pk(),
                        is_update=True,
                    )
                    update_response = ak.update_saml_source(payload["slug"], payload)
                if update_response.status_code >= 400:
                    results.append(EntityResult("idp", kc_id, alias, None, FAILED, API_REJECTED))
                else:
                    results.append(
                        EntityResult(
                            "idp", kc_id, alias, existing["pk"], UPDATED, unmapped=write_unmapped
                        )
                    )
                continue

            if not apply:
                results.append(
                    EntityResult("idp", kc_id, alias, None, CREATED, unmapped=write_unmapped)
                )
                continue

            if kind == "oauth":
                payload = map_oauth_source(
                    kc_idp,
                    secret=secret,
                    user_matching_mode=user_matching_mode,
                    authentication_flow=_auth_flow_pk(),
                    enrollment_flow=_enrollment_flow_pk(),
                )
                create_response = ak.create_oauth_source(payload)
            else:
                pre_auth_flow_pk = _pre_auth_flow_pk()
                payload = map_saml_source(
                    kc_idp,
                    pre_authentication_flow=pre_auth_flow_pk,
                    signing_kp=_saml_signing_kp(ak, kc_idp),
                    user_matching_mode=user_matching_mode,
                    authentication_flow=_auth_flow_pk(),
                    enrollment_flow=_enrollment_flow_pk(),
                )
                create_response = ak.create_saml_source(payload)
            if create_response.status_code >= 400:
                results.append(EntityResult("idp", kc_id, alias, None, FAILED, API_REJECTED))
                continue
            created = create_response.json()
            results.append(
                EntityResult("idp", kc_id, alias, created["pk"], CREATED, unmapped=write_unmapped)
            )
        except httpx.HTTPError:
            results.append(EntityResult("idp", kc_id, alias, None, FAILED, API_REJECTED))

    return results


def migrate_groups(
    kc: KeycloakClient,
    ak: AuthentikClient,
    realm: str,
    *,
    apply: bool,
    update_existing: bool = False,
) -> tuple[list[EntityResult], dict[str, str], dict[str, str], dict[str, set[int]]]:
    """Returns (results, ok_groups, group_pks, group_members).

    ok_groups maps group name -> Keycloak group id, for every non-nested
    group (regardless of outcome) -- migrate_memberships uses it to know
    which groups' members are even worth reading.

    group_pks maps group name -> Authentik group pk, for every group known
    to exist in Authentik (matched or, under --apply, newly created).

    group_members maps group name -> the Authentik user pks already in that
    group (empty for a brand-new group) -- migrate_memberships uses it so a
    re-run reports an already-present member as SKIPPED instead of calling
    add_user again.
    """
    results: list[EntityResult] = []
    ok_groups: dict[str, str] = {}
    group_pks: dict[str, str] = {}
    group_members: dict[str, set[int]] = {}

    for kc_group in kc.get_groups(realm):
        name = kc_group["name"]
        kc_id = kc_group["id"]

        if is_nested(kc_group):
            results.append(
                EntityResult("group", kc_id, name, None, CONFLICT, NESTED_GROUPS_UNSUPPORTED)
            )
            continue
        ok_groups[name] = kc_id

        try:
            existing = ak.find_group_by_name(name)
            if existing is not None:
                group_pks[name] = existing["pk"]
                group_members[name] = set(existing.get("users") or [])
                if not update_existing:
                    results.append(EntityResult("group", kc_id, name, existing["pk"], SKIPPED))
                    continue
                if not apply:
                    results.append(EntityResult("group", kc_id, name, existing["pk"], UPDATED))
                    continue
                update_response = ak.update_group(existing["pk"], map_group(kc_group))
                if update_response.status_code >= 400:
                    results.append(EntityResult("group", kc_id, name, None, FAILED, API_REJECTED))
                else:
                    results.append(EntityResult("group", kc_id, name, existing["pk"], UPDATED))
                continue

            if not apply:
                results.append(EntityResult("group", kc_id, name, None, CREATED))
                continue

            response = ak.create_group(map_group(kc_group))
            if response.status_code >= 400:
                results.append(EntityResult("group", kc_id, name, None, FAILED, API_REJECTED))
                continue
            created = response.json()
            group_pks[name] = created["pk"]
            group_members[name] = set()
            results.append(EntityResult("group", kc_id, name, created["pk"], CREATED))
        except httpx.HTTPError:
            results.append(EntityResult("group", kc_id, name, None, FAILED, API_REJECTED))

    return results, ok_groups, group_pks, group_members


def migrate_users(
    kc: KeycloakClient,
    ak: AuthentikClient,
    realm: str,
    *,
    apply: bool,
    update_existing: bool = False,
) -> tuple[list[EntityResult], dict[str, int], set[str]]:
    """Returns (results, user_pks, resolved_usernames).

    user_pks maps username -> Authentik user pk, for every user with a
    *known* pk: matched, or (under --apply) newly created.

    resolved_usernames is every username whose outcome was CREATED or
    SKIPPED, whether or not a pk is known yet -- a dry-run CREATE has no
    real pk, but migrate_memberships still needs to know the user will
    exist so it can plan that membership rather than drop it.
    """
    results: list[EntityResult] = []
    user_pks: dict[str, int] = {}
    resolved_usernames: set[str] = set()
    # Emails this run has already decided to create, so two Keycloak users
    # sharing an email are flagged as duplicates against each other even in
    # a dry run, when nothing is actually written to check against yet.
    planned_emails: set[str] = set()

    for kc_user in kc.get_users(realm):
        username = kc_user["username"]
        kc_id = kc_user["id"]
        mapped = map_user(kc_user)
        email = mapped["email"]

        is_active = mapped["is_active"]

        try:
            existing = ak.find_user_by_username(username)
            if existing is not None:
                if (existing.get("email") or "") == email:
                    user_pks[username] = existing["pk"]
                    resolved_usernames.add(username)
                    if not update_existing:
                        results.append(
                            EntityResult(
                                "user",
                                kc_id,
                                username,
                                existing["pk"],
                                SKIPPED,
                                email=email,
                                is_active=is_active,
                            )
                        )
                        continue
                    if not apply:
                        results.append(
                            EntityResult(
                                "user",
                                kc_id,
                                username,
                                existing["pk"],
                                UPDATED,
                                email=email,
                                is_active=is_active,
                            )
                        )
                        continue
                    update_response = ak.update_user(existing["pk"], mapped)
                    if update_response.status_code >= 400:
                        results.append(
                            EntityResult("user", kc_id, username, None, FAILED, API_REJECTED)
                        )
                    else:
                        results.append(
                            EntityResult(
                                "user",
                                kc_id,
                                username,
                                existing["pk"],
                                UPDATED,
                                email=email,
                                is_active=is_active,
                            )
                        )
                else:
                    results.append(
                        EntityResult(
                            "user", kc_id, username, None, CONFLICT, USERNAME_TAKEN_EMAIL_DIFFERS
                        )
                    )
                continue

            # No username collision. Flag (but don't block on) a different
            # user already holding this email -- Authentik allows it. Checks
            # both Authentik's existing state and this run's own plan, so
            # two colliding users in the same batch are caught even dry.
            is_duplicate = bool(email) and (
                email in planned_emails or ak.find_user_by_email(email) is not None
            )
            reason = EMAIL_DUPLICATE_USERNAME_NEW if is_duplicate else None
            if email:
                planned_emails.add(email)

            if not apply:
                resolved_usernames.add(username)
                results.append(
                    EntityResult(
                        "user",
                        kc_id,
                        username,
                        None,
                        CREATED,
                        reason,
                        email=email,
                        is_active=is_active,
                    )
                )
                continue

            response = ak.create_user(mapped)
            if response.status_code >= 400:
                results.append(EntityResult("user", kc_id, username, None, FAILED, API_REJECTED))
                continue
            created = response.json()
            user_pks[username] = created["pk"]
            resolved_usernames.add(username)
            results.append(
                EntityResult(
                    "user",
                    kc_id,
                    username,
                    created["pk"],
                    CREATED,
                    reason,
                    email=email,
                    is_active=is_active,
                )
            )
        except httpx.HTTPError:
            results.append(EntityResult("user", kc_id, username, None, FAILED, API_REJECTED))

    return results, user_pks, resolved_usernames


def migrate_memberships(
    kc: KeycloakClient,
    ak: AuthentikClient,
    realm: str,
    *,
    apply: bool,
    ok_groups: dict[str, str],
    group_pks: dict[str, str],
    group_members: dict[str, set[int]],
    user_pks: dict[str, int],
    resolved_usernames: set[str],
) -> list[EntityResult]:
    """One entity per (group, member) pair read from Keycloak. A member
    whose own user entity did not resolve at all (conflicted or failed) is
    silently excluded -- that failure is already recorded against the user
    entity itself, and there is no membership to speak of without a user on
    either end. A member that resolved but has no pk yet (a dry-run CREATE)
    still gets a planned membership entity.
    """
    results: list[EntityResult] = []

    for name, kc_group_id in ok_groups.items():
        for member in kc.get_group_members(realm, kc_group_id):
            username = member["username"]
            if username not in resolved_usernames:
                continue

            kc_id = f"{kc_group_id}:{member['id']}"
            ref = f"{name}/{username}"
            user_pk = user_pks.get(username)

            if user_pk is not None and user_pk in group_members.get(name, set()):
                results.append(EntityResult("membership", kc_id, ref, group_pks.get(name), SKIPPED))
                continue

            if not apply:
                results.append(EntityResult("membership", kc_id, ref, None, CREATED))
                continue

            group_pk = group_pks.get(name)
            if group_pk is None or user_pk is None:
                # Either the group or the user failed to create despite not
                # being a reported conflict -- nothing to add.
                results.append(EntityResult("membership", kc_id, ref, None, FAILED, API_REJECTED))
                continue

            try:
                response = ak.add_user_to_group(group_pk, user_pk)
                if response.status_code >= 400:
                    results.append(
                        EntityResult("membership", kc_id, ref, None, FAILED, API_REJECTED)
                    )
                else:
                    results.append(EntityResult("membership", kc_id, ref, group_pk, CREATED))
            except httpx.HTTPError:
                results.append(EntityResult("membership", kc_id, ref, None, FAILED, API_REJECTED))

    return results


def migrate_roles(
    kc: KeycloakClient,
    ak: AuthentikClient,
    realm: str,
    *,
    apply: bool,
    update_existing: bool = False,
    planned_group_names: frozenset[str] = frozenset(),
) -> tuple[list[EntityResult], dict[str, str], set[str], dict[str, set[int]]]:
    """Returns (results, role_pks, role_conflicted, role_members).

    A realm role becomes an Authentik group tagged
    attributes.kc2ak_origin == "realm_role" (mappers.roles.map_role).
    Built-in roles (mappers.roles.builtin_role_names) are excluded before
    the read is counted -- they never become report entities at all,
    exactly like Keycloak's six built-in clients
    (mappers.clients.BUILTIN_CLIENT_IDS). A composite role and a name
    collision with a group not of role origin are both CONFLICT and write
    nothing (.chief/milestone-2/_contract/01-role-mapping.md).

    planned_group_names is migrate_groups' ok_groups keys -- every
    non-nested Keycloak group in this same run, whether it already existed
    in Authentik or will only be created once --apply runs. Collision
    detection must include it: groups are processed before roles, so on a
    first-ever migration a same-named Keycloak group and realm role do not
    yet collide in live Authentik state during a dry run, but will the
    moment --apply creates the group. Checking live state alone would let a
    dry run promise a clean plan that --apply then contradicts -- the same
    defect milestone 1 fixed for memberships by planning against resolved
    names instead of authentik pks
    (.chief/milestone-2/_contract/01-role-mapping.md's "Collision detection
    must include the same run").

    role_pks maps role name -> Authentik group pk, for every role matched or
    (under --apply) newly created -- migrate_role_assignments uses it the
    same way migrate_memberships uses migrate_groups' group_pks.

    role_conflicted is every role name whose outcome was CONFLICT.
    migrate_role_assignments uses it to give an assignment to one of these
    its own CONFLICT / role_assignment_role_missing entity, rather than
    silently dropping it -- .chief/milestone-2/_contract/01-role-mapping.md's
    "An assignment to a role that was not migrated".

    role_members maps role name -> the Authentik user pks already in that
    group, same purpose as migrate_groups' group_members.
    """
    results: list[EntityResult] = []
    role_pks: dict[str, str] = {}
    role_conflicted: set[str] = set()
    role_members: dict[str, set[int]] = {}
    builtin = builtin_role_names(realm)

    for kc_role in kc.get_roles(realm):
        name = kc_role["name"]
        if name in builtin:
            continue
        kc_id = kc_role["id"]
        unmapped = unmapped_role_fields(kc_role)

        if is_composite(kc_role):
            role_conflicted.add(name)
            results.append(
                EntityResult(
                    "role", kc_id, name, None, CONFLICT, COMPOSITE_ROLE_UNSUPPORTED, unmapped
                )
            )
            continue

        if name in planned_group_names:
            # A Keycloak group of the same name is in this same run's group
            # phase -- it collides whether or not it exists in Authentik
            # yet, so a dry run must report this before --apply creates it.
            role_conflicted.add(name)
            results.append(
                EntityResult(
                    "role", kc_id, name, None, CONFLICT, ROLE_NAME_TAKEN_BY_GROUP, unmapped
                )
            )
            continue

        try:
            existing = ak.find_group_by_name(name)
            if existing is not None:
                if not is_role_origin(existing):
                    role_conflicted.add(name)
                    results.append(
                        EntityResult(
                            "role", kc_id, name, None, CONFLICT, ROLE_NAME_TAKEN_BY_GROUP, unmapped
                        )
                    )
                    continue

                role_pks[name] = existing["pk"]
                role_members[name] = set(existing.get("users") or [])
                pk = existing["pk"]
                if not update_existing:
                    results.append(
                        EntityResult("role", kc_id, name, pk, SKIPPED, unmapped=unmapped)
                    )
                    continue
                if not apply:
                    results.append(
                        EntityResult("role", kc_id, name, pk, UPDATED, unmapped=unmapped)
                    )
                    continue
                update_response = ak.update_group(pk, map_role(kc_role))
                if update_response.status_code >= 400:
                    results.append(EntityResult("role", kc_id, name, None, FAILED, API_REJECTED))
                else:
                    results.append(
                        EntityResult("role", kc_id, name, pk, UPDATED, unmapped=unmapped)
                    )
                continue

            if not apply:
                results.append(EntityResult("role", kc_id, name, None, CREATED, unmapped=unmapped))
                continue

            response = ak.create_group(map_role(kc_role))
            if response.status_code >= 400:
                results.append(EntityResult("role", kc_id, name, None, FAILED, API_REJECTED))
                continue
            created = response.json()
            role_pks[name] = created["pk"]
            role_members[name] = set()
            results.append(
                EntityResult("role", kc_id, name, created["pk"], CREATED, unmapped=unmapped)
            )
        except httpx.HTTPError:
            results.append(EntityResult("role", kc_id, name, None, FAILED, API_REJECTED))

    return results, role_pks, role_conflicted, role_members


def migrate_role_assignments(
    kc: KeycloakClient,
    ak: AuthentikClient,
    realm: str,
    *,
    apply: bool,
    role_pks: dict[str, str],
    role_conflicted: set[str],
    role_members: dict[str, set[int]],
    user_pks: dict[str, int],
    resolved_usernames: set[str],
) -> list[EntityResult]:
    """One `membership` entity per (user, non-built-in role) pair, read from
    each resolved user's role-mappings/realm -- the direct-assignment list,
    not composite-expanded (see KeycloakClient.get_user_realm_roles). Role
    assignments are not their own kind: they are group memberships, counted
    under counts.memberships exactly like a Keycloak group membership
    (.chief/milestone-2/_contract/01-role-mapping.md).

    A user whose own entity did not resolve at all is silently excluded,
    same reasoning as migrate_memberships. A role that itself ended
    CONFLICT is different: its holder gets their own CONFLICT /
    role_assignment_role_missing entity rather than being dropped, because
    the role's own CONFLICT names a failed role, not who lost access.
    """
    results: list[EntityResult] = []
    builtin = builtin_role_names(realm)

    for kc_user in kc.get_users(realm):
        username = kc_user["username"]
        if username not in resolved_usernames:
            continue
        kc_user_id = kc_user["id"]

        for kc_role in kc.get_user_realm_roles(realm, kc_user_id):
            role_name = kc_role["name"]
            if role_name in builtin:
                continue

            kc_id = f"{kc_user_id}:{role_name}"
            ref = f"{username}/{role_name}"

            if role_name in role_conflicted:
                results.append(
                    EntityResult(
                        "membership", kc_id, ref, None, CONFLICT, ROLE_ASSIGNMENT_ROLE_MISSING
                    )
                )
                continue

            group_pk = role_pks.get(role_name)
            user_pk = user_pks.get(username)

            if (
                user_pk is not None
                and group_pk is not None
                and user_pk in role_members.get(role_name, set())
            ):
                results.append(EntityResult("membership", kc_id, ref, group_pk, SKIPPED))
                continue

            if not apply:
                results.append(EntityResult("membership", kc_id, ref, None, CREATED))
                continue

            if group_pk is None or user_pk is None:
                results.append(EntityResult("membership", kc_id, ref, None, FAILED, API_REJECTED))
                continue

            try:
                response = ak.add_user_to_group(group_pk, user_pk)
                if response.status_code >= 400:
                    results.append(
                        EntityResult("membership", kc_id, ref, None, FAILED, API_REJECTED)
                    )
                else:
                    results.append(EntityResult("membership", kc_id, ref, group_pk, CREATED))
            except httpx.HTTPError:
                results.append(EntityResult("membership", kc_id, ref, None, FAILED, API_REJECTED))

    return results


def migrate_federated_links(
    kc: KeycloakClient,
    ak: AuthentikClient,
    realm: str,
    *,
    idp_results: list[EntityResult],
    user_matching_mode: str,
) -> list[EntityResult]:
    """Federated identity links are never written -- authentik's public API
    has no way to create a UserOAuthSourceConnection/UserSAMLSourceConnection
    with a chosen user+source+identifier (see migrate_idps' docstring and the
    "Federated identity links" amendment in
    .chief/milestone-2/_contract/02-idp-mapping.md). `user_matching_mode`
    stands in for it, set on every source by migrate_idps.

    Two outcomes only:

    - A link whose source did not resolve this run at all -- an unsupported
      providerId, or `--only` excluded idps and no matching source exists
      live -- is a real, per-user, actionable failure: CONFLICT /
      federated_link_source_missing, kind "federated_link". This is the one
      case migrate_federated_links still emits an entity for.
    - A link whose source did resolve is not an entity at all. Emitting one
      CONFLICT per user for a condition that is uniform across every linked
      user and already mitigated by user_matching_mode would be exactly the
      noise .chief/_rules/_standard/diagnostics.md forbids. Instead this
      mutates that source's own EntityResult (found in idp_results by alias)
      with one `unmapped` entry of type federated_link_unwritable, carrying
      how many Keycloak users depend on the matching mode working. When idps
      was not in scope this run, idp_results has no entity for that alias to
      attach the count to -- an earlier run's idp entity already carried it,
      so nothing more is emitted here.
    """
    results: list[EntityResult] = []
    by_alias = {r.keycloak_ref: r for r in idp_results if r.kind == "idp"}
    resolved_this_run = {
        alias for alias, r in by_alias.items() if r.outcome in (CREATED, SKIPPED, UPDATED)
    }
    counts: dict[str, int] = {}
    live_exists: dict[str, bool] = {}

    def _source_exists_live(alias: str) -> bool:
        if alias not in live_exists:
            live_exists[alias] = ak.find_source_by_slug(slugify(alias)) is not None
        return live_exists[alias]

    for kc_user in kc.get_users(realm):
        username = kc_user["username"]
        kc_user_id = kc_user["id"]

        for link in kc.get_federated_identities(realm, kc_user_id):
            alias = link["identityProvider"]
            kc_id = f"{kc_user_id}:{alias}"
            ref = f"{username}/{alias}"

            if alias in resolved_this_run or (alias not in by_alias and _source_exists_live(alias)):
                counts[alias] = counts.get(alias, 0) + 1
                continue

            results.append(
                EntityResult(
                    "federated_link", kc_id, ref, None, CONFLICT, FEDERATED_LINK_SOURCE_MISSING
                )
            )

    for alias, count in counts.items():
        entity = by_alias.get(alias)
        if entity is None:
            continue
        entity.unmapped.append(
            {
                "type": FEDERATED_LINK_UNWRITABLE,
                "name": alias,
                "why": (
                    f"{count} Keycloak user(s) hold a federated identity to this source; "
                    f"authentik cannot pre-create the link, user_matching_mode="
                    f"{user_matching_mode} was set instead"
                ),
            }
        )

    return results


def migrate_clients(
    kc: KeycloakClient,
    ak: AuthentikClient,
    realm: str,
    *,
    apply: bool,
    authorization_flow: str,
    invalidation_flow: str,
    update_existing: bool = False,
) -> list[EntityResult]:
    """One entity per migratable Keycloak OIDC client, representing the
    OAuth2Provider + Application pair together (report contract's example:
    a single "client" entity, not two). Keycloak's built-in clients and
    non-OIDC clients are filtered out entirely -- see
    mappers.clients.is_migratable_client -- and never appear as entities at
    all, since they are realm infrastructure, not realm data.

    Matching is by natural key: clientId == the existing provider's
    client_id (.chief/milestone-1/_goal/03-idempotency-and-matching.md).
    A matched provider whose application is missing (an interrupted prior
    run left a half-created pair) has its application finished regardless
    of --update-existing -- creating a missing counterpart is not modifying
    an existing object, and skipping it would leave re-runs permanently
    incomplete.

    Protocol mapper translation (mappers.protocol_mappers, task-5b) is
    computed unconditionally for every client, same as
    unmapped_client_fields -- so `unmapped` carries whitelist misses on a
    dry run and on a SKIPPED/UPDATED match too, not only on a fresh
    CREATED. ScopeMapping objects (both the protocol-mapper translations and
    mappers.clients.standard_scope_mappings' openid/profile/email copies,
    task-5c) are only actually created and attached (via property_mappings)
    on the brand-new-provider path -- a match (SKIPPED/UPDATED) or the
    half-created-pair repair never (re)creates them, since mapper attachment
    isn't part of --update-existing's scope in this milestone (deliberately
    deferred, not a gap). Creation is find-or-create by name
    (AuthentikClient.find_scope_mapping_by_name) rather than a plain create:
    ScopeMapping.name is globally unique in authentik, so a run interrupted
    between mapping creation and provider creation would otherwise 400 on
    every rerun attempt forever -- find-or-create is what makes that rerun
    converge instead, per .chief/milestone-1/_goal/03-idempotency-and-matching.md's
    "interrupted run completes without duplicates" done-condition.
    """
    results: list[EntityResult] = []

    # Resolved once per run, not per client: authorization_flow/
    # invalidation_flow are CLI-supplied slugs, but OAuth2Provider's fields
    # of the same name reject a slug and require the flow's pk (confirmed
    # live -- see AuthentikClient.get_flow_pk). A precondition already
    # confirmed both slugs resolve before migrate_clients is ever called.
    authorization_flow_pk = ak.get_flow_pk(authorization_flow)
    invalidation_flow_pk = ak.get_flow_pk(invalidation_flow)

    for kc_client in kc.get_clients(realm):
        if not is_migratable_client(kc_client):
            continue

        client_id = kc_client["clientId"]
        kc_id = kc_client["id"]
        name = kc_client.get("name") or client_id
        slug = slugify(client_id)
        is_public = kc_client.get("publicClient", False)
        mapper_payloads, mapper_unmapped = translate_client_protocol_mappers(kc_client, client_id)
        standard_payloads, standard_unmapped = standard_scope_mappings(kc_client, client_id)

        try:
            # Read once per in-scope client purely to report -- client roles
            # are never migrated (.chief/milestone-2/_goal/01-roles-scope.md).
            role_unmapped = unmapped_client_roles(list(kc.get_client_roles(realm, kc_id)))
            unmapped = (
                unmapped_client_fields(kc_client)
                + mapper_unmapped
                + standard_unmapped
                + role_unmapped
            )
            secret = None if is_public else kc.get_client_secret(realm, kc_id)
            mapped_provider = map_provider(
                kc_client,
                secret,
                authorization_flow=authorization_flow_pk,
                invalidation_flow=invalidation_flow_pk,
            )

            existing_provider = ak.find_provider_by_client_id(client_id)
            if existing_provider is not None:
                provider_pk = existing_provider["pk"]
                existing_app = ak.find_application_by_slug(slug)

                if existing_app is None:
                    if not apply:
                        results.append(
                            EntityResult(
                                "client", kc_id, client_id, None, CREATED, unmapped=unmapped
                            )
                        )
                        continue
                    app_response = ak.create_application(
                        map_application(client_id, provider_pk, name)
                    )
                    if app_response.status_code >= 400:
                        results.append(
                            EntityResult("client", kc_id, client_id, None, FAILED, API_REJECTED)
                        )
                    else:
                        results.append(
                            EntityResult(
                                "client", kc_id, client_id, client_id, CREATED, unmapped=unmapped
                            )
                        )
                    continue

                if not update_existing:
                    results.append(
                        EntityResult(
                            "client", kc_id, client_id, client_id, SKIPPED, unmapped=unmapped
                        )
                    )
                    continue
                if not apply:
                    results.append(
                        EntityResult(
                            "client", kc_id, client_id, client_id, UPDATED, unmapped=unmapped
                        )
                    )
                    continue
                update_response = ak.update_provider(provider_pk, mapped_provider)
                if update_response.status_code >= 400:
                    results.append(
                        EntityResult("client", kc_id, client_id, None, FAILED, API_REJECTED)
                    )
                else:
                    results.append(
                        EntityResult(
                            "client", kc_id, client_id, client_id, UPDATED, unmapped=unmapped
                        )
                    )
                continue

            if not apply:
                results.append(
                    EntityResult("client", kc_id, client_id, None, CREATED, unmapped=unmapped)
                )
                continue

            all_mapper_payloads = [*standard_payloads, *mapper_payloads]
            mapper_pks: list[str] = []
            mapper_create_failed = False
            for mapper_payload in all_mapper_payloads:
                # Find-or-create: ScopeMapping.name is globally unique, so a
                # run interrupted between mapping creation and provider
                # creation would 400 on a plain create on rerun -- this is
                # what makes that rerun converge instead of leaving the
                # client permanently FAILED (task-5c).
                existing_mapping = ak.find_scope_mapping_by_name(mapper_payload["name"])
                if existing_mapping is not None:
                    mapper_pks.append(existing_mapping["pk"])
                    continue
                mapping_response = ak.create_scope_mapping(mapper_payload)
                if mapping_response.status_code >= 400:
                    mapper_create_failed = True
                    break
                mapper_pks.append(mapping_response.json()["pk"])
            if mapper_create_failed:
                results.append(EntityResult("client", kc_id, client_id, None, FAILED, API_REJECTED))
                continue
            if mapper_pks:
                mapped_provider["property_mappings"] = mapper_pks

            provider_response = ak.create_provider(mapped_provider)
            if provider_response.status_code >= 400:
                results.append(EntityResult("client", kc_id, client_id, None, FAILED, API_REJECTED))
                continue
            created_provider = provider_response.json()
            app_response = ak.create_application(
                map_application(client_id, created_provider["pk"], name)
            )
            if app_response.status_code >= 400:
                results.append(EntityResult("client", kc_id, client_id, None, FAILED, API_REJECTED))
                continue
            results.append(
                EntityResult("client", kc_id, client_id, client_id, CREATED, unmapped=unmapped)
            )
        except httpx.HTTPError:
            results.append(EntityResult("client", kc_id, client_id, None, FAILED, API_REJECTED))

    return results
