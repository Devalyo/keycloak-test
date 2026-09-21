# Mini Keycloak

Mini Keycloak is a compact persistent identity and OIDC service. It includes a
SQLite development workflow and a shipped PostgreSQL, Gunicorn, and Caddy TLS
deployment.

Read the [deployment guide](mini-keycloak/docs/deployment.md) for the isolated
Compose workflow, configuration, private health checks, and TLS trust. Use the
[operations runbook](mini-keycloak/docs/operations.md) for backup, restore,
upgrades, keys, cleanup, and troubleshooting.

## Run the local SQLite environment

From the repository root, create the environment and install the project:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e './mini-keycloak[dev]'
cd mini-keycloak
export MINI_KEYCLOAK_DATABASE_URL='sqlite:///mini-keycloak.db'
../.venv/bin/python -m flask --app mini_keycloak.app db upgrade
../.venv/bin/python -m flask --app mini_keycloak.app bootstrap-demo
../.venv/bin/mini-keycloak
```

The local command binds only `127.0.0.1:5000`, with debug mode disabled.
Relative SQLite URLs resolve under Flask's instance directory, not necessarily
the shell's working directory. The SQLite file is persistent: realms, clients,
users, reset sessions, and outbox records survive a web-process restart while
the same database URL is in use. Schema creation and Demo data seeding are
deliberate operator actions.
The web command never runs migrations or bootstraps data. If the database has
not been migrated or seeded, correct the setup by running the two commands
above rather than expecting web startup to modify it.

`bootstrap-demo` is idempotent and provides these demo values:

| Item | Value |
| --- | --- |
| Realm | `demo` (`Demo Realm`) |
| Client ID | `demo-app` |
| Client redirect URI | `http://localhost:9999/callback` |
| User | `demo_user` / `demo-user@example.test` |
| Initial password | `DemoPassw0rd!` |

## Inspect reset messages

The reset outbox is available only through the local CLI, not an
HTTP endpoint. From `mini-keycloak` with the same
`MINI_KEYCLOAK_DATABASE_URL`, run:

```bash
../.venv/bin/python -m flask --app mini_keycloak.app outbox-list
```

It prints each message timestamp, recipient, and consumed state. It does not
print action tokens.

## Ordinary tests

From the repository root, run the unit and application suite independently of
the live PostgreSQL and deployment gates:

```bash
.venv/bin/python -m pytest mini-keycloak/tests \
  --ignore=mini-keycloak/tests/postgres \
  --ignore=mini-keycloak/tests/deployment -q
```

The ordinary OIDC provider supports authorization code with S256 PKCE, RS256
tokens, refresh rotation/reuse revocation, userinfo, logout, and opt-in password
grants. See the [OIDC guide](mini-keycloak/README.md) for protocol usage, bounded
realm import, password policy, ordinary-login throttling, audit events, and
session behavior. Live PostgreSQL migration/concurrency and fresh-volume TLS
deployment gates are implemented; their commands and limits are in the
[deployment guide](mini-keycloak/docs/deployment.md#verification).

## Import realms and manage keys

The local CLI supports a bounded subset of Keycloak-style realm JSON, explicit
non-destructive updates, and signing-key inspection/rotation. From `mini-keycloak`
after migrations, import the disposable example realm:

```bash
../.venv/bin/python -m flask --app mini_keycloak.app realm-import tests/fixtures/realm-import/valid-realm.json
../.venv/bin/python -m flask --app mini_keycloak.app realm-key-list --realm example
```

Duplicate realm imports fail unless `--update` is supplied. Updates preserve
unlisted data and omitted credentials; repeated bundled bootstrap also preserves
changed or deliberately absent credentials and the active signing key. Read the
[field compatibility, update, URI-limit, and backup guide](mini-keycloak/README.md#realm-json-import)
before importing private files or rotating keys. Warnings mean unsupported fields
were ignored.
