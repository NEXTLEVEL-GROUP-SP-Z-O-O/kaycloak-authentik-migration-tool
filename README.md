# kc2ak — Keycloak → Authentik migration tool

A command-line tool that migrates users, groups, group memberships, and OAuth/OIDC
clients from a [Keycloak](https://www.keycloak.org/) realm into
[Authentik](https://goauthentik.io/).

> **Status: planning.** Nothing is implemented yet. The design below is settled;
> the commands in [Usage](#usage) are the intended interface, not a working one.

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

**Matching is by natural key.** Users match on `username`, groups on `name`,
clients on `clientId`. If an object already exists in Authentik it is skipped and
listed in the report — existing data is never modified unless you pass
`--update-existing`, which switches matched objects to a PATCH.

**Re-runs are safe.** Because existing objects are skipped, an interrupted
migration can simply be run again; it will not create duplicates.

**Secrets are never logged.** Admin tokens, client secrets, and credentials are
redacted in all output, including error paths and HTTP debug logs.

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

## Usage

> Not implemented yet — this section will be filled in as the tool is built.

```bash
# Preview the migration. Reads only; writes nothing.
kc2ak migrate --realm myrealm

# Apply it.
kc2ak migrate --realm myrealm --apply

# Apply, and have Authentik mail every migrated user a reset link.
kc2ak migrate --realm myrealm --apply --send-recovery-email

# Apply, and update objects that already exist in Authentik.
kc2ak migrate --realm myrealm --apply --update-existing
```

One realm per run. Endpoints and credentials for both systems are read from the
environment.

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
