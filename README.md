# kc2ak — Keycloak → Authentik migration tool

A command-line tool that migrates users, groups, group memberships, and OAuth/OIDC
clients from a [Keycloak](https://www.keycloak.org/) realm into
[Authentik](https://goauthentik.io/).

> **Status: implemented, pending final acceptance.** Users, groups, memberships,
> clients, protocol mappers, reporting, and recovery mail all work and are covered
> by 171 tests. Each piece has been verified against live Keycloak and Authentik
> instances — including a real OIDC flow through a migrated client on its original
> `clientId` and secret. The one check still outstanding is a single `kc2ak
> migrate` run against both services simultaneously, which the development host
> cannot currently hold in memory (see [Resource note](#resource-note)).

## What it does

Reads a single Keycloak realm over the Admin REST API and creates the equivalent
objects in Authentik:

| Keycloak | → | Authentik |
|---|---|---|
| Users | → | Users |
| Groups | → | Groups |
| Group memberships | → | Group memberships |
| Clients (OIDC) | → | OAuth2/OIDC Providers + Applications |

Migration runs in dependency order: groups → users → memberships → applications.

## Design decisions

**Dry-run by default.** The tool reads Keycloak and prints the full plan of what it
would create. Nothing is written to Authentik without `--apply`.

**Matching is by natural key.** A user counts as already migrated only when
**both `username` and `email` match**; groups match on `name`, clients on
`clientId`. If an object already exists in Authentik it is skipped and listed in
the report — existing data is never modified unless you pass `--update-existing`,
which switches matched objects to a PATCH.

Partial matches are reported, never guessed at. A Keycloak user whose username
collides with a different Authentik account is rejected by Authentik (`username`
is unique there) — the tool records it as a conflict and moves on rather than
aborting the run. A user whose email collides but whose username does not *will*
be created, since Authentik does not require emails to be unique; the report
flags it so the duplicate is visible before anyone acts on it.

**Re-runs are safe.** Because existing objects are skipped, an interrupted
migration can simply be run again; it will not create duplicates.

**Secrets are never logged.** Admin tokens, client secrets, and credentials are
redacted in all output, including error paths and HTTP debug logs.

**One realm per run.** Authentik has no equivalent of a Keycloak realm — brands
configure branding and flows but share one global pool of users, groups, and
applications, and hard tenancy is a separate Enterprise feature. So the tool maps
one realm onto one Authentik instance and does not prefix names.

**Groups are flat.** Keycloak allows two groups with the same leaf name in
different branches; Authentik requires `Group.name` to be globally unique. Rather
than invent a naming scheme, the tool refuses to guess: a nested group tree is
reported as an error, not silently flattened.

**Nothing about tokens is guessed.** Keycloak protocol mappers are translated to
Authentik property mappings only for an explicit whitelist of mapper types. An
unrecognised mapper does not block the provider and is *not* a conflict — the
provider is still created, and `CONFLICT` is reserved for entities where nothing
was written. Instead the mapper is listed in the report's `unmapped`, and any
unmapped mapper anywhere in the run forces exit `1`, so a migration that quietly
dropped part of a token's contents can never exit green. A wrongly translated
mapper changes token contents in a way that only surfaces in production, so the
tool reports it for a human rather than approximating it.

Client secrets *are* carried over, so existing client applications keep working
with nothing more than an issuer URL change.

## Passwords cannot be migrated

This is a hard constraint of the two systems, not a missing feature.

Keycloak's Admin REST API deliberately **strips `secretData`** — the password hash
and salt — from `GET /admin/realms/{realm}/users/{id}/credentials`. Password
material is never exposed over REST at all.

So migrated users arrive without a usable password. Instead, the tool asks
Authentik to send each of them a password-reset mail via
`POST /api/v3/core/users/{id}/recovery_email/`.

Because that mails real people and cannot be undone, it needs its own opt-in on
top of `--apply`:

```bash
kc2ak migrate --realm myrealm --apply --send-recovery-email
```

A dry run always prints the exact number of recipients before anything is sent.
Authentik needs a working SMTP configuration and a recovery flow for this to
succeed; the tool checks both up front and fails loudly if either is missing.

<details>
<summary>Why not convert the hashes? (for the curious)</summary>

Authentik <em>can</em> accept a pre-hashed password —
`POST /api/v3/core/users/{id}/set_password_hash/` takes a raw Django hash — so the
idea is not absurd. It fails for two independent reasons:

1. **The hashes aren't available.** As above, the Admin API never returns them.
   They exist only inside a `kc.sh export --users` realm file or the database.
2. **Most of them wouldn't convert anyway.** Django's PBKDF2 hasher treats the
   salt as a UTF-8 *string* and rejects any salt containing `$`, while Keycloak
   stores 16 raw random bytes. Keycloak's PBKDF2 hashes (the default through
   Keycloak 23) therefore cannot be expressed as a Django hash. Argon2id hashes
   (Keycloak 24+) *would* convert, since Django hands the full PHC string —
   base64 salt included — to argon2-cffi.

A future milestone could support realm-export input for Argon2-era realms. It is
out of scope here.
</details>

## Known limitations

A migrated client's standard OIDC claims are narrower than what authentik ships
by default. `given_name`, `family_name`, and `email_verified` are not
reproducible and are omitted rather than approximated — each is reported per
client in the JSON report's `unmapped` list (as `type: "standard_scope_claim"`),
but does **not** affect the exit code, since it happens on essentially every
run rather than signalling something realm-specific to review.

- `given_name` / `family_name`: Keycloak's `firstName` and `lastName` collapse
  into authentik's single `name` field, so the parts aren't separable — emitting
  the full name as `given_name` would be a wrong value, not a partial one.
- `email_verified`: authentik does not track email verification at all, so a
  reproduced claim would hardcode `true` for every migrated user regardless of
  their real Keycloak state. Relying parties treat this claim as a security
  assertion; asserting an unverified address is verified is worse than omitting
  the claim entirely, so it is left out.

Operators will see these on every run and should expect them.

## Usage

```bash
# Preview the migration. Reads only; writes nothing.
kc2ak migrate --realm myrealm \
  --authorization-flow default-provider-authorization-explicit-consent \
  --invalidation-flow default-provider-invalidation-flow

# Users and groups only — no clients, so no flows needed.
kc2ak migrate --realm myrealm --only groups,users,memberships

# Apply it.
kc2ak migrate --realm myrealm --apply \
  --authorization-flow default-provider-authorization-explicit-consent \
  --invalidation-flow default-provider-invalidation-flow

# Apply, and have Authentik mail every newly created user a reset link.
kc2ak migrate --realm myrealm --apply \
  --send-recovery-email --email-stage <uuid> \
  --authorization-flow … --invalidation-flow …
```

One realm per run. Endpoints and credentials for both systems are read from the
environment.

## API notes

Behaviours of the Keycloak and Authentik APIs that differ from what their
documentation implies. Each was observed against a running instance while
building this tool, not inferred from docs or source. Versions are stated because
these are version-specific observations, not permanent truths.

Useful whether or not you use this tool — each of these cost real debugging time.

**`recovery_email` takes `email_stage` as a query parameter, not a JSON body**
*(authentik 2024.10.5)*
`POST /core/users/{id}/recovery_email/?email_stage=<uuid>`. Sending
`{"email_stage": "<uuid>"}` as a body returns `400 "Email stage does not exist"`
**even when the stage is real and correct** — the body is ignored, and the absent
query parameter is what fails. The error names the wrong cause.

**Provider flows take a resolved pk, not a slug** *(authentik 2024.10.5)*
`authorization_flow` and `invalidation_flow` on `POST /providers/oauth2/` reject a
flow slug with `400 "not a valid UUID"`. Look the slug up first and send the pk.

**A provider created through the API gets no property mappings at all**
*(authentik 2024.10.5)*
Unlike one created in the UI, which receives authentik's managed
`openid`/`profile`/`email` scope mappings. A migrated client that relied on
realm-level default client scopes for standard claims will silently issue tokens
without them unless you attach mappings yourself.

**Scope mappings only run when their scope is requested** *(authentik 2024.10.5)*
authentik evaluates a scope mapping's expression only if the token request
includes that `scope_name`. Keycloak's *default* client scopes fire
unconditionally — a `scope=openid` request still returns
`granted scope: openid profile email`. Reproducing Keycloak's behaviour therefore
means putting claims on a scope the client always requests, not on the
nominally-matching one.

**Same-key list values are concatenated across mappings, not overwritten**
*(authentik 2024.10.5)*
Two property mappings both emitting `groups` produce every group **twice** in the
issued token, rather than one overriding the other.

**`GET /groups` never populates `subGroups`** *(Keycloak 25)*
The list representation reports nesting only through `subGroupCount`. Code that
detects nested groups by checking for a non-empty `subGroups` will treat every
nested group as flat. Older versions do expose `subGroups`, so check both.

**Two protocol mapper types have no `claim.name`** *(Keycloak 25)*
`oidc-audience-mapper` and `oidc-full-name-mapper` have no `claim.name` config
property at all — confirmed against `GET /admin/serverinfo`'s
`protocolMapperTypes`. Their claim keys are the literals `aud` and `name`.

**Script-based protocol mappers are not registered by default** *(Keycloak 25)*
`oidc-script-based-protocol-mapper` is gated behind a removed preview feature. A
realm JSON containing one imports **silently**, with that mapper dropped and no
error — the import reports success and you get fewer mappers than you wrote.

## Local test environment

`docker-compose.yml` brings up a throwaway Keycloak + Authentik pair for
development and verification, plus a seeded Keycloak realm (`kc2ak-test`,
imported from `deploy/keycloak/realm-kc2ak-test.json`) that exercises the hard
cases rather than just the happy path: flat groups with memberships, a
**nested** group (`sales` → `sales/admins` — the tool must report `CONFLICT` /
`nested_groups_unsupported` on it), a user with no email address, two users
sharing an email with different usernames, a disabled user, and one
confidential OIDC client with a wildcard redirect URI and two protocol
mappers — one inside the whitelist (`oidc-usermodel-property-mapper`), one
outside it (`oidc-usermodel-realm-role-mapper`; a script-based mapper would
demonstrate the same "unmapped" case, but this Keycloak version doesn't
register that provider by default, so it's silently dropped on import —
`oidc-usermodel-realm-role-mapper` exercises the identical contract path).

Milestone 2 added: a plain realm role (`employee`), a **composite** realm role
(`senior-engineer`, containing `employee` and `code-reviewer` — must report
`CONFLICT` / `composite_role_unsupported`), a realm role named `engineering`
that **collides** with the existing `engineering` group (`CONFLICT` /
`role_name_taken_by_group`), a second client (`internal-tool`) so it and
`confidential-app` both carry a same-named `admin` client role (unmigratable,
reported only), an OIDC identity provider (`corporate-sso`) with a secret, a
SAML identity provider (`corporate-saml`) with a real self-signed certificate,
an identity provider of an unsupported type, and a federated identity link
from `ajones` to `corporate-sso`. The unsupported-type provider is seeded as
`linkedin-openid-connect`, not `linkedin`: this Keycloak version validates
`providerId` against its registered identity-broker factories at **import**
time, and `providerId: "linkedin"` aborts the entire server boot rather than
being dropped — `GET /admin/serverinfo`'s `providers.social.providers`
confirms `linkedin-openid-connect` is the one actually registered.

```bash
cp .env.example .env
docker compose up -d
```

Keycloak: http://localhost:8081 (realm `kc2ak-test`, admin console login
`admin`/`admin`). Authentik: http://localhost:9000.

### Getting an Authentik API token

The compose file sets `AUTHENTIK_BOOTSTRAP_TOKEN` on the Authentik containers,
which turns into a ready-made API token for the `akadmin` superuser on first
boot — no UI login needed. Its value is `AK_TOKEN` in `.env.example`
(`kc2ak-local-bootstrap-token` by default):

```bash
curl -H "Authorization: Bearer kc2ak-local-bootstrap-token" \
  http://localhost:9000/api/v3/core/users/
```

### Resource note

The full rig (Keycloak, Authentik server + worker, Postgres, Redis) needs
roughly 2-3 GB free inside the Docker VM. Docker Desktop's default 4 GB
allocation may not cover that once other local stacks are also running.
Symptom: Keycloak exits with code `137` (`docker inspect` shows
`OOMKilled: true`). Fix: raise Docker Desktop's memory allocation (Settings →
Resources), or stop other stacks while the rig is up.

Tear down with `docker compose down -v`.

## Development

```bash
uv sync                  # install dependencies
uv run kc2ak --help      # run the CLI
uv run pytest            # tests
uv run ruff check .      # lint
uv run ruff format .     # format
uv run mypy src          # typecheck
```

### Layout

```
src/kc2ak/
  cli.py               # typer entrypoint, flags, config loading
  config.py            # endpoints, credentials (env-first)
  keycloak_client.py   # thin Keycloak Admin API wrapper
  authentik_client.py  # thin Authentik API wrapper
  mappers/             # one module per entity type, pure functions
  migrator.py          # orchestration, dry-run diff, resume state
tests/
  fixtures/            # real-shaped Keycloak API responses
```

Clients handle only auth, pagination, and retries. Mappers are pure functions —
Keycloak shape in, Authentik shape out, no I/O — so each one is covered by a
fixture-backed test. The migrator owns ordering, the dry-run diff, and matching.

## Stack

Python 3.12+ · [uv](https://docs.astral.sh/uv/) · typer · httpx · pydantic ·
pytest · ruff · mypy
