# kc2ak — Keycloak → Authentik migration tool

A command-line tool that migrates users, groups, group memberships, realm roles,
identity providers, and OAuth/OIDC clients from a
[Keycloak](https://www.keycloak.org/) realm into
[Authentik](https://goauthentik.io/).

> **Status: implemented and verified end to end.** All seven entity kinds,
> protocol mappers, reporting, and recovery mail work and are covered by 295
> tests. Every piece has been verified against live Keycloak and Authentik
> instances, including a real OIDC login through a migrated client on its original
> `clientId` and secret, and a real login through a migrated identity provider
> landing on the migrated account. A single full-scope run — all seven kinds, both
> services up, from a wiped Authentik — reconciles across dry run, `--apply`, and
> re-run, with the re-run creating nothing.
>
> **Verified against authentik 2026.5.6** (and Keycloak 25.0.6): the full
> seven-kind cycle above was re-run on a wiped 2026.5.6 rig after the version
> bump, with 26 entities reconciling identically across all three runs.
>
> Open checks:
> - **No end-to-end SAML login** has ever been completed — field-level evidence
>   only.
> - **The OIDC logins were verified on 2024.10.5**, not on the current target.
>   A real login through a migrated client and through a migrated identity
>   provider both completed then; the 2026.5.6 verification covers API writes and
>   read-backs, which does not prove a browser flow still completes.
> - **`microsoft` → `azuread`** is schema-confirmed on 2026.5.6 but still
>   untested against a real Microsoft provider.

## What it does

Reads a single Keycloak realm over the Admin REST API and creates the equivalent
objects in Authentik:

| Keycloak | → | Authentik |
|---|---|---|
| Users | → | Users |
| Groups | → | Groups |
| Group memberships | → | Group memberships |
| Realm roles | → | Groups (marked `kc2ak_origin`) |
| Role assignments | → | Group memberships |
| Identity providers (OIDC / SAML) | → | OAuth / SAML Sources |
| Federated identity links | → | Source `user_matching_mode` (see below) |
| Clients (OIDC) | → | OAuth2/OIDC Providers + Applications |

Migration runs in a fixed dependency order, enforced regardless of the order
`--only` lists them in:

```
idps → groups → roles → users → memberships → role assignments
    → federated links → clients
```

Sources precede links; roles follow groups so a name collision is detectable;
assignments and links follow users. Role assignments are not a separate `--only`
value — they are part of `roles`, which is why the order has eight steps and
`--only` has seven values.

**Authentik has no separate role object**, so a Keycloak realm role becomes a
group carrying `attributes.kc2ak_origin`, which lets a re-run tell a migrated role
from a migrated group. Built-in roles are excluded. Composite roles and roles
whose name collides with an existing group are reported as conflicts, never
approximated. Client roles are read and reported, never written.

**Federated identity links cannot be written.** Authentik's
`POST /sources/user_connections/{oauth,saml}/` returns `405` on every version —
these objects are only ever created by the flow executor during a real login. The
tool instead sets `user_matching_mode` on the migrated source
(`--idp-user-matching`, default `username_link`), so a returning user lands on
their migrated account rather than a duplicate. Links whose source was not
migrated are reported as conflicts.

## Design decisions

**Dry-run by default.** The tool reads Keycloak and prints the full plan of what it
would create. Nothing is written to Authentik without `--apply`.

**Matching is by natural key.** A user counts as already migrated only when
**both `username` and `email` match**; groups match on `name`, clients on
`clientId`, identity provider sources on `slug` (derived from the Keycloak
`alias`, and matched type-agnostically so an OIDC and a SAML provider cannot both
claim it), and realm roles on the group `name` they map to. If an object already
exists in Authentik it is skipped and listed in the report — existing data is
never modified unless you pass `--update-existing`, which switches matched
objects to a PATCH.

Because a role and a group both land in Authentik's group namespace, a role only
matches a group that carries `attributes.kc2ak_origin == "realm_role"`. A name
collision with a group of any other origin is a conflict, not a match — and
collision detection covers groups **this same run** will create, not just those
already live, so a dry run cannot promise a clean plan that `--apply` then
contradicts.

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

Beyond the claims above, these are reported and never guessed at:

- **Composite roles.** Authentik groups do not nest role semantics the way
  Keycloak composites do, so a composite is reported as `CONFLICT` /
  `composite_role_unsupported` rather than flattened into its members.
- **Client roles.** Read once per client and reported as `unmapped`; they have no
  Authentik equivalent and are never written.
- **Identity provider secrets.** Not readable from Keycloak — supply them with
  `--idp-secrets` or the source is created disabled.
- **Per-user federated links.** Not writable through Authentik's API at all; see
  [What it does](#what-it-does) for the `user_matching_mode` substitute.
- **Unsupported provider types.** Reported as `CONFLICT` /
  `idp_type_unsupported`, never mapped to a near-enough type.
- **The CIBA grant.** Keycloak's `oidc.ciba.grant.enabled` has no member in
  authentik's `GrantTypesEnum`, so a client using it is reported rather than
  approximated with a neighbouring grant. Every other Keycloak flow toggle —
  standard, implicit, direct access, service accounts, device code — is carried
  into the provider's `grant_types`.
- **JWT client authentication on an identity provider.** authentik's
  `AuthorizationCodeAuthMethodEnum` has only `basic_auth` and `post_body`, so
  Keycloak's `client_secret_jwt` and `private_key_jwt` are reported. Substituting
  a neighbouring method would change how the source authenticates.
  `client_secret_post` and `client_secret_basic` map directly.
- **Non-standard SAML name ID formats.** A `nameIDPolicyFormat` outside
  authentik's six-member `SAMLNameIDPolicyEnum` is reported and left to
  authentik's default; sending it would be rejected outright.
- **The second logout channel.** Keycloak can hold a back-channel *and* a
  front-channel logout URL at once; authentik holds one `logout_method` and one
  `logout_uri`. The client's own `frontchannelLogout` boolean picks which one is
  carried — it is the switch Keycloak itself uses — and the other URL, if set, is
  reported. A client with only the unselected channel populated gets no logout
  fields at all rather than a method pointing nowhere.

**Out of scope**, deliberately: client roles as first-class objects,
LDAP/Kerberos user federation, authentication flows, required actions, and
multi-realm runs. One realm per invocation.

## Configuration

Endpoints and credentials come from the **environment**, never from CLI flags, so
they do not land in shell history or in `ps` output. There is no `--url` or
`--token` option and that is deliberate.

| Variable | Required | What it is |
|---|---|---|
| `KC_URL` | yes | Keycloak base URL, e.g. `https://keycloak.example.com` |
| `AK_URL` | yes | Authentik base URL, e.g. `https://authentik.example.com` |
| `AK_TOKEN` | yes | Authentik API token for an admin account |
| `KC_REALM_ADMIN` | one pair | Keycloak admin username |
| `KC_ADMIN_PASSWORD` | one pair | that admin's password |
| `KC_CLIENT_ID` | one pair | service-account client, for `client_credentials` |
| `KC_CLIENT_SECRET` | one pair | that client's secret |

Keycloak needs **one** of the two credential pairs. Supply neither and the run
stops with `Keycloak credentials missing: set KC_REALM_ADMIN + KC_ADMIN_PASSWORD,
or KC_CLIENT_ID + KC_CLIENT_SECRET`.

**`.env` is not loaded automatically.** The file in this repo is read by
`docker-compose` for the [local test rig](#local-test-environment), not by
`kc2ak`. Running from this directory with a populated `.env` still fails with
`KC_URL is not set`. Export it yourself:

```bash
set -a; source .env; set +a
uv run kc2ak migrate --realm myrealm --only groups
```

Or pass the variables for a single run:

```bash
KC_URL=https://keycloak.example.com \
KC_REALM_ADMIN=admin KC_ADMIN_PASSWORD=… \
AK_URL=https://authentik.example.com AK_TOKEN=… \
uv run kc2ak migrate --realm myrealm
```

No Docker is needed to *run* the tool — the compose stack only exists to provide
a Keycloak and an Authentik to migrate between while developing.

## Usage

```bash
# Preview the migration. Reads only; writes nothing.
kc2ak migrate --realm myrealm \
  --authorization-flow default-provider-authorization-explicit-consent \
  --invalidation-flow default-provider-invalidation-flow

# Users and groups only — no clients, so no flows needed.
kc2ak migrate --realm myrealm --only groups,users,memberships

# Roles too. They become groups; assignments become memberships.
kc2ak migrate --realm myrealm --only groups,roles,users,memberships

# Apply it.
kc2ak migrate --realm myrealm --apply \
  --authorization-flow default-provider-authorization-explicit-consent \
  --invalidation-flow default-provider-invalidation-flow

# Apply, and have Authentik mail every newly created user a reset link.
kc2ak migrate --realm myrealm --apply \
  --send-recovery-email --email-stage <uuid> \
  --authorization-flow … --invalidation-flow …
```

`--only` accepts any subset of `idps`, `groups`, `roles`, `users`, `memberships`,
`federated-links`, `clients`. Nothing outside the selection is written.

### Identity providers

Sources need their own flows, and their secrets cannot be read out of Keycloak:

```bash
# Migrate identity providers with their secrets.
kc2ak migrate --realm myrealm --apply --only idps \
  --idp-secrets ./idp-secrets.json \
  --authentication-flow default-source-authentication \
  --enrollment-flow default-source-enrollment \
  --pre-authentication-flow default-source-pre-authentication
```

`--idp-secrets` takes a JSON file mapping IdP alias → secret. It must not be
world-readable. Keycloak returns `**********` for a stored secret rather than the
value, and the tool treats that as **absent**, never as a secret — so without this
file a source is created **disabled** and reported, rather than created broken.

The flow flags matter for the same reason: a source created without
`--authentication-flow` and `--enrollment-flow` renders a login button and then
fails mid-flow. Missing either one disables the source and reports
`idp_flow_missing`. `--pre-authentication-flow` is required by SAML sources.

Any run that creates a disabled source says so on stdout, not only in the report.

Supported Keycloak `providerId` values are whitelisted: `saml`, plus the OAuth
family `oidc`, `keycloak-oidc`, `google`, `github`, `gitlab`, `facebook`,
`twitter`, `okta`, `apple`, `discord`, `reddit`, `twitch`, and `microsoft`
(→ authentik's `azuread`). Anything else — `linkedin-openid-connect`, for
instance — is reported as `CONFLICT` / `idp_type_unsupported`, never approximated
with a near-enough type.

### Updating existing objects

`--update-existing` switches matched objects from skip to PATCH. An update sends
**only what the run knows**: any field this invocation cannot supply is omitted
rather than defaulted, so a thinner update never disables a working source or
overwrites a live secret with a placeholder.

One realm per run. Endpoints and credentials come from the environment — see
[Configuration](#configuration).

## API notes

Behaviours of the Keycloak and Authentik APIs that differ from what their
documentation implies. Each was observed against a running instance while
building this tool, not inferred from docs or source. Versions are stated because
these are version-specific observations, not permanent truths.

The current verification target is **authentik 2026.5.6** and **Keycloak 25.0.6**
— the versions the test rig pins. Observations labelled 2024.10.5 were made on
the earlier target and have not all been re-checked individually; the full
migration itself has been re-verified end to end on 2026.5.6.

Useful whether or not you use this tool — each of these cost real debugging time.

**`grant_types` on a provider exists only from authentik 2026.5** *(observed on
2026.5.6; absent from `OAuth2ProviderRequest` on 2024.10.5)*
2026.5 made OAuth2 grant types selectable per provider and backfilled every
pre-existing provider with all seven to preserve behaviour, so **an omitted
`grant_types` is permissive, not restrictive**. A provider created through the
API without the field comes back as `grant_types: []` and still works. Two
consequences: writing the field can only ever *narrow* what a provider accepts,
and `refresh_token` is a member of the enum in its own right — omit it from a
list you do write and the application can no longer renew a token. The enum has
no CIBA member at all. This tool always sends the field; versions below 2026.5
ignore the unknown key, which is cheaper than version-detecting.

**`post.logout.redirect.uris` uses two sentinels, not just a URL list**
*(Keycloak 25.0.6)*
The attribute is `##`-separated, and Keycloak writes **`+`** into it by default,
meaning "the same URIs this client already redirects to" — not a literal URL.
`-` means none. Since `+` is the default, essentially every migrated client
produces a `redirect_uri_type: "logout"` entry for each of its authorization
redirect URIs; that is Keycloak's actual policy, not duplication. The logout URL
attributes themselves are `backchannel.logout.url` and
`frontchannel.logout.url`, with `frontchannelLogout` as a separate boolean on the
client object rather than an attribute — all three confirmed by writing them
through the admin API and reading the client back.

**`azuread` is still a valid `provider_type`, and `entraid` now exists too**
*(authentik 2026.5.6)*
`ProviderTypeEnum` on 2026.5.6 is `openidconnect, apple, entraid, azuread,
discord, facebook, github, gitlab, google, mailcow, okta, patreon, reddit, slack,
twitch, twitter, wechat`. Keycloak's `microsoft` provider maps to `azuread`,
which milestone 2 flagged as its one unconfirmed whitelist entry — the member is
present, so the mapping is at least schema-valid. `entraid` is the newer name for
the same identity source; this tool still writes `azuread`. Note `mailcow`,
`patreon`, `slack` and `wechat` have no Keycloak counterpart in the whitelist.

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

Task-2 added one more case: the `noemail` user carries an explicit
`realmRoles: [offline_access]` assignment, since a realm-file-imported user
otherwise receives no built-in role assignment at all — the built-in-role
filter was previously only exercised at the realm level, never at the
per-user assignment level.

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
