"""Read -> map -> diff -> write orchestration for groups, users, and
memberships, in the fixed order from
.chief/milestone-1/_goal/01-migration-scope.md.

Dry-run is the default: writes only happen when apply=True. Every write path
is behind that flag, per
.chief/milestone-1/_goal/02-safety-and-blast-radius.md. Clients/providers are
task-5; the report writer and stdout summary are task-3 -- this module only
produces EntityResult records in memory for them to consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from kc2ak.authentik_client import AuthentikClient
from kc2ak.keycloak_client import KeycloakClient
from kc2ak.mappers.clients import (
    is_migratable_client,
    map_application,
    map_provider,
    slugify,
    unmapped_client_fields,
)
from kc2ak.mappers.groups import NESTED_GROUPS_UNSUPPORTED, is_nested, map_group
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
        unmapped = unmapped_client_fields(kc_client)

        try:
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
