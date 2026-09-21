# Deploy Mini Keycloak

This guide operates the shipped service; it is not a guide to deploying
Keycloak itself.
See the [protocol/import guide](../README.md) for supported identity features
and the [operations runbook](operations.md) before upgrades or changes to secrets.

## Local SQLite workflow

Use Python 3.10 or newer. From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e './mini-keycloak[dev]'
cd mini-keycloak
export MINI_KEYCLOAK_PROFILE=local
export MINI_KEYCLOAK_DATABASE_URL='sqlite:///mini-keycloak.db'
../.venv/bin/python -m flask --app mini_keycloak.app db upgrade
../.venv/bin/python -m flask --app mini_keycloak.app bootstrap-demo
../.venv/bin/mini-keycloak
```

The local server binds `127.0.0.1:5000`, disables debug mode, and uses
`http://127.0.0.1:5000` as its default external URL. Relative SQLite paths resolve
under Flask's instance directory. Keep the same database and secrets for state
to survive restarts. The local profile has a public development application
secret and a derived key-encryption fallback; use only disposable environment identities.
Compose reads `.env`; the standalone command does not load that file for you.

Migrations and bootstrap are explicit operations. Neither the local web command
nor Gunicorn creates tables, seeds realms, rotates keys, or re-encrypts existing
keys. The bundled realm is `demo`, its client is `demo-app`, and its disposable
credentials are in the [repository setup](../../README.md). Ordinary imported
clients default to mandatory S256 PKCE; the bundled client remains optional-PKCE.

## Shipped Compose workflow

Use a local Docker engine and Docker Compose with health/completed-service
dependencies. Run every command in this guide from `mini-keycloak`, which
contains [compose.yaml](../compose.yaml). An existing shell environment can
override `.env`; remove stale project/port/secret overrides before operating a
different environment. Do not run shell tracing around secret setup.

### Create and preserve private configuration

The following creates `.env` from [.env.example](../.env.example), with three
independent 256-bit hexadecimal secrets. It prints no values, uses mode `0600`,
and refuses to overwrite an existing file. Run it once for a new environment; subsequent
starts must reuse the file. The database password must stay URI-safe hexadecimal
because Compose inserts it into the database URL.

<!-- contract: compose-secrets -->
```bash
python3 - <<'PY'
import os
from pathlib import Path
import secrets

names = {
    "POSTGRES_PASSWORD",
    "MINI_KEYCLOAK_SECRET_KEY",
    "MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET",
}
lines = Path(".env.example").read_text().splitlines()
content = "\n".join(
    line.split("=", 1)[0] + "=" + secrets.token_hex(32)
    if line.split("=", 1)[0] in names else line
    for line in lines
) + "\n"
try:
    descriptor = os.open(".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    raise SystemExit("Existing .env preserved; reuse its stable secrets.") from None
with os.fdopen(descriptor, "w") as stream:
    stream.write(content)
PY
```

Keep a protected recovery copy of the secrets outside the repository and
separately from database backups. `.env` and exported deployment certificates
are ignored by Git. Do not print `.env`, resolved Compose configuration, container
environments, or database URLs into tickets or shared terminals. Docker daemon
access grants access to container environment secrets.

### Validate, build, and start

```bash
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps -a
docker compose logs --tail 30 migrate bootstrap
```

Use `config --quiet`: plain `config` prints resolved secrets. The image builds
the Python wheel in a separate stage; the runtime contains installed packages,
migrations, and Gunicorn configuration, runs as UID/GID `10001:10001`, and has a
read-only root filesystem with writable temporary storage. Official Python,
PostgreSQL 17, and Caddy images are pinned by digest in the shipped artifacts.

Startup order is PostgreSQL healthy, `migrate` completed successfully,
`bootstrap` completed successfully, `web` healthy, then `caddy`. In `ps -a`,
both one-shot jobs should show exit status 0, PostgreSQL and web should become
healthy, and Caddy should be running. A failed job or unhealthy web blocks
dependent services; inspect the generic logs before retrying.

`migrate` runs `flask --app mini_keycloak.app:create_app db upgrade`;
`bootstrap` runs `flask --app mini_keycloak.app:create_app bootstrap-demo`.
To run those same operator jobs explicitly after PostgreSQL is healthy, use
these commands in order. During an upgrade, stop the writers and follow the
[backup/upgrade procedure](operations.md#upgrade-and-rollback-preparation) first.

<!-- contract: compose-jobs -->
```bash
docker compose run --rm --no-deps migrate
docker compose run --rm --no-deps bootstrap
```

No bootstrap or migration is hidden inside Gunicorn startup. A normal repeat
bootstrap preserves changed or deliberately absent credentials, sessions, and
the active key. Do not use repeat bootstrap as a credential reset mechanism.

### Trust the local TLS gateway

The default origin is `https://localhost:8443`. Only Caddy publishes a host port,
bound to `127.0.0.1`; PostgreSQL, Gunicorn, and health probes have no host port
bindings. Use `localhost` in the URL, not a substituted IP/Host. Caddy uses its
private local CA, so an ordinary client initially rejects its certificate.

Export only the public root certificate and supply it to a client explicitly:

<!-- contract: compose-trust -->
```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt deploy/local-ca.crt
curl --fail --silent --show-error --cacert deploy/local-ca.crt \
  https://localhost:8443/realms/demo/.well-known/openid-configuration
```

For browser use, import that public certificate into a dedicated disposable
browser/profile trust store using that client's procedure. Keep trust scoped
to the environment and remove it when the environment is destroyed. Do not disable certificate
verification or export the CA private keys. Caddy's private CA material stays
in `caddy_data`; deleting that volume creates a new CA on the next start and
requires exporting/trusting the new public certificate. If the HTTPS port is
changed, use that port consistently in browser/client configuration and examples.

### Health, restart, and teardown

| Check | Meaning |
| --- | --- |
| Private `/health/live` | Process can answer; does not query the database |
| Private `/health/ready` | Read-only database query plus one usable active RS256 key with matching public material for each enabled realm; generic 503 on failure |
| PostgreSQL healthcheck | `pg_isready` accepts a database connection; not application readiness |
| TLS discovery through Caddy | Gateway routing/TLS and advertised issuer work; separate from private readiness |
| Public `/health` or `/health/*` | Caddy returns fixed 404; these routes are deliberately not public probes |

Readiness does not migrate or bootstrap and is not an Alembic-version audit.
A migrated database with no enabled realms can be ready; readiness alone does
not prove the expected environment realm exists. Before schema provisioning, it fails.
Check migration status and discovery separately. Inside web, diagnostics must
use the configured Host, even though the connection is loopback:

```bash
docker compose exec -T web python - <<'PY'
import urllib.error
import urllib.request

for probe in ("live", "ready"):
    request = urllib.request.Request(
        "http://127.0.0.1:8000/health/" + probe,
        headers={"Host": "localhost"},
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            print(probe, response.status)
    except urllib.error.HTTPError as error:
        print(probe, error.code)
PY
```

Restart only the web process while preserving job state, database, sessions,
keys, and CA:

```bash
docker compose restart --no-deps web
```

Use the same project name and `.env` for subsequent operations. This persistent
teardown removes containers/networks but keeps named PostgreSQL and Caddy volumes:

```bash
docker compose down
```

The following is a separate, destructive teardown for a disposable environment. It
deletes that Compose project's database and CA/config volumes, including all
identity, session, and private-key state in them. Recovery requires a matching
backup and secrets; remove obsolete local CA trust afterward:

```bash
docker compose down --volumes
```

## Application configuration

These are application environment variables, with standalone local defaults.
They are read at app creation; restart after a deliberate change. Production
validation fails with a variable name and no submitted value. Positive numeric
settings reject zero/negative/noninteger values. Booleans accept `true`/`false`
or `1`/`0`. Realm lifetime overrides take precedence where supported.

| Variable | Local default / contract |
| --- | --- |
| `MINI_KEYCLOAK_PROFILE` | `local`; only `local` and `production` are accepted |
| `MINI_KEYCLOAK_DATABASE_URL` | `sqlite:///mini-keycloak.db`; production requires `postgresql+psycopg` with host and database |
| `MINI_KEYCLOAK_EXTERNAL_URL` | `http://127.0.0.1:5000`; production requires an HTTPS origin without a path prefix |
| `MINI_KEYCLOAK_SECRET_KEY` | Public local fallback; production requires an explicit secret of at least 32 UTF-8 bytes |
| `MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET` | Derived locally from the final application secret; production requires an explicit independent value of at least 32 UTF-8 bytes |
| `MINI_KEYCLOAK_SESSION_COOKIE_SECURE` | `false`; must be `true` in production |
| `MINI_KEYCLOAK_ACCESS_TOKEN_LIFETIME_SECONDS` | `300`; positive integer |
| `MINI_KEYCLOAK_AUTHORIZATION_CODE_LIFETIME_SECONDS` | `60`; positive integer |
| `MINI_KEYCLOAK_REFRESH_TOKEN_LIFETIME_SECONDS` | `1800`; positive integer |
| `MINI_KEYCLOAK_SSO_IDLE_LIFETIME_SECONDS` | `1800`; positive integer |
| `MINI_KEYCLOAK_SSO_MAX_LIFETIME_SECONDS` | `36000`; positive integer |
| `MINI_KEYCLOAK_DATABASE_POOL_SIZE` | `5`; positive integer, PostgreSQL only, per web worker/process |
| `MINI_KEYCLOAK_DATABASE_MAX_OVERFLOW` | `10`; positive integer, PostgreSQL only, additional connections per pool |
| `MINI_KEYCLOAK_DATABASE_POOL_TIMEOUT_SECONDS` | `30`; positive integer wait for a pooled connection |
| `MINI_KEYCLOAK_DATABASE_POOL_RECYCLE_SECONDS` | `1800`; positive integer PostgreSQL connection recycle age |
| `MINI_KEYCLOAK_LOG_LEVEL` | `INFO`; uppercase `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`; application logger only |
| `MINI_KEYCLOAK_TRUSTED_HOSTS` | Local loopback names plus external hostname; production requires an explicit comma-separated exact hostname list including the external hostname; no ports or wildcards |
| `MINI_KEYCLOAK_PROXY_MODE` | `none` locally; production requires explicit `none` or `xforwarded` |
| `MINI_KEYCLOAK_TRUSTED_PROXY_CIDRS` | Unset locally; `xforwarded` requires comma-separated strict IPv4/IPv6 CIDRs of trusted direct peers |
| `MINI_KEYCLOAK_PROXY_HOPS` | `1`; integer 1–8, count from the right of accepted forwarded source/scheme chains |
| `MINI_KEYCLOAK_LOGIN_FAILURE_THRESHOLD` | `5`; positive integer failures per ordinary credential bucket |
| `MINI_KEYCLOAK_LOGIN_FAILURE_WINDOW_SECONDS` | `300`; positive integer counting window |
| `MINI_KEYCLOAK_LOGIN_LOCK_SECONDS` | `60`; positive integer fixed block duration |

PostgreSQL pools always enable pre-ping. Budget connections across all workers,
one-shot jobs, and maintenance clients; the default two workers can each use
up to 15 pooled/overflow connections. SQLite does not receive PostgreSQL pool
settings. Production factory overrides cannot enable SQL echo/query recording,
alternate binds, or conflicting engine options.

PostgreSQL URL query options are limited to `connect_timeout` (1–60), `sslmode`
(`require`, `verify-ca`, or `verify-full`), and `sslrootcert`. Certificate-verifying
modes require an absolute `sslrootcert` path, and that path is rejected without
one of those modes. Blank, duplicate, and unknown options fail. The shipped URL
uses `connect_timeout=5` on the private Compose database network; it does not
configure PostgreSQL TLS. Gateway HTTPS and database transport are separate.

### Compose inputs and runtime settings

Compose reads these substitution inputs from `.env` or the shell:

| Variable | Shipped behavior |
| --- | --- |
| `POSTGRES_PASSWORD` | Required independent stable hexadecimal secret; initializes the database role on a fresh volume |
| `MINI_KEYCLOAK_SECRET_KEY` | Required stable application secret passed to all app services |
| `MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET` | Required independent stable encryption secret passed to all app services |
| `MINI_KEYCLOAK_HTTPS_PORT` | `8443`; loopback TLS publication and external issuer port |
| `MINI_KEYCLOAK_PROXY_SUBNET` | `172.30.83.0/24`; private proxy network |
| `MINI_KEYCLOAK_PROXY_ADDRESS` | `172.30.83.254`; fixed Caddy peer trusted by web as exactly one `/32` |
| `COMPOSE_PROJECT_NAME` | Optional Compose project selector; app image defaults to `mini-keycloak-app:local` when unset; keep project selection consistent |

If the private subnet overlaps another local network, change the subnet and
Caddy address together to an unused matching private range. Never broaden the
trusted proxy range to solve connectivity problems. PostgreSQL's shipped
`POSTGRES_DB` and `POSTGRES_USER` are both fixed to `mini_keycloak` in Compose;
the database URL uses the same values.

The app services set `production`, secure cookies, trusted Host `localhost`,
`xforwarded` with one hop, and the configured Caddy `/32`. The Gunicorn listener
is `0.0.0.0:8000` inside the private container networks. Merely adding another
application/Gunicorn variable to `.env` does not inject it: add a reviewed
`environment` entry to the shared `x-app` configuration to pass it to services.
Keep the listener, Dockerfile healthcheck, and Caddy upstream port aligned.

For standalone Gunicorn, from this project directory after migration/bootstrap:

```bash
../.venv/bin/gunicorn --config gunicorn.conf.py
```

| Variable | Standalone default / allowed range |
| --- | --- |
| `MINI_KEYCLOAK_GUNICORN_HOST` | `127.0.0.1`; numeric IPv4/IPv6 address, no hostname or scope identifier |
| `MINI_KEYCLOAK_GUNICORN_PORT` | `8000`; 1–65535 |
| `MINI_KEYCLOAK_GUNICORN_WORKERS` | `2`; 1–16 |
| `MINI_KEYCLOAK_GUNICORN_THREADS` | `2`; 1–16 per gthread worker |
| `MINI_KEYCLOAK_GUNICORN_TIMEOUT` | `30`; 1–300 seconds |
| `MINI_KEYCLOAK_GUNICORN_GRACEFUL_TIMEOUT` | `30`; 1–120 seconds |
| `MINI_KEYCLOAK_GUNICORN_KEEPALIVE` | `5`; 1–30 seconds |

Gunicorn loads `mini_keycloak.wsgi:app` without preloading. Its log level is
fixed to `info` by the shipped configuration; `MINI_KEYCLOAK_LOG_LEVEL` controls
the application logger. The standalone Gunicorn port differs from the default
external URL's port: configure the actual external origin before using a browser.

## Request, password, and logging boundaries

The direct peer must match a trusted CIDR before `X-Forwarded-For` and
`X-Forwarded-Proto` can affect source/scheme. All other forwarding metadata,
including forwarded Host, port, prefix, and `Forwarded`, is ignored/removed.
Gunicorn does not make its own forwarding trust decisions. Caddy overwrites
the source and scheme headers. Untrusted direct clients cannot authorize their
own forwarded claims; invalid Host values fail with 400.

Issuer/discovery endpoints come only from validated external configuration or
the realm issuer override. A request Host or forwarded header cannot change
them. Production supports an origin, not a URL path mount. Ordinary login
Origin/Sec-Fetch-Site checks, pre-authentication cookies, exact redirect matching,
and request limits are detailed in the [OIDC guide](../README.md).

Password policies enforce recognized length, digit, lowercase, uppercase, and
special-character minima for import and password creation/replacement.
Unsupported imported clauses warn and are not enforcement. Persistent
throttling protects browser login and password grants using realm + normalized
identifier + validated source address in an HMAC bucket. It survives worker
restarts, blocks for a fixed interval, clears on successful authentication, and
returns generic credential failures. It is not general traffic protection.

Application/Gunicorn error events are fixed JSON messages. Gunicorn JSON access
records retain method, path, status, response size, duration, source address,
and a generated correlation ID. `X-Request-ID` is generated server-side even
for application Host failures; incoming IDs are not reused. Caddy-generated
404/502 responses do not have an application correlation ID. The local Werkzeug
server redacts queries but does not use the Gunicorn JSON access format.

No-query logging omits query values, Authorization/Cookie and other sensitive
headers, request bodies, and response Location values. Caddy request access
and error log namespaces are suppressed to prevent proxy failures exposing
request data; ordinary runtime diagnostics remain. Do not enable raw request
tracing, SQL echo, or proxy access dumps while troubleshooting. Client/callback
logs need the same discipline. Paths/source addresses themselves can identify
environment activity, so restrict access to retained logs.

## Verification

The [root README](../../README.md#ordinary-tests) gives the ordinary suite command.
From the repository root, these separate implemented gates require Docker:

```bash
.venv/bin/python mini-keycloak/tests/postgres/run.py
.venv/bin/python -m pytest mini-keycloak/tests/deployment -m deployment -v --tb=short
```

The PostgreSQL runner creates an ephemeral PostgreSQL 17 instance and unique
schemas for real migrations, rollback/retry, and concurrency checks. The
deployment gate builds the image and exercises a fresh-volume TLS stack,
private health, normal OIDC, logging, key rotation, and a web-only restart. It
removes its own uniquely named project and volumes afterward. These gates
validate the documented runtime behavior.
