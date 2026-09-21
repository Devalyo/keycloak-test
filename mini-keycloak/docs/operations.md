# Operate and recover Mini Keycloak

All commands below run from `mini-keycloak` with the intended project's Compose configuration
and stable `.env`. See [deployment](deployment.md) for initial setup, private
health probes, environment settings, and local CA trust.

## Stable secrets and state

Keep the database, application configuration, and matching secrets recoverable.
The database stores identities, Argon2 credentials, encrypted RSA private keys,
public key metadata, sessions, protocol artifacts, login-failure buckets, events,
and local reset-mail metadata. Backups are private identity/session data even
when private keys are encrypted.

| Item | If changed or lost |
| --- | --- |
| `MINI_KEYCLOAK_SECRET_KEY` | Application-secret-signed browser state stops validating; ordinary-login HMAC buckets change, so existing buckets no longer match new attempts. It does not by itself revoke all persisted sessions/JWTs. |
| `MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET` | Existing encrypted signing keys cannot be decrypted with a different value; readiness/token issuance fail. No automatic re-encryption or master-secret migration exists. |
| `POSTGRES_PASSWORD` | Changing `.env` alone does not change the role password in an existing PostgreSQL volume; new application connections fail. Keep database-role and application configuration changes coordinated. |
| External origin/port or realm issuer | Clients need the matching issuer/redirect configuration; old tokens can fail issuer checks. Restore validation must account for the original issuer. |
| `postgres_data` | Deleting it loses identity/session/key state. Recover from a database backup and the original matching secrets. |
| `caddy_data` | Holds the private local CA; deleting it changes the CA on next startup. Export and trust the new public root, and remove obsolete trust. |

Use independent stable secrets for the three roles, retain protected recovery
copies separately from backups, and never paste them into shell arguments,
logs, tickets, or version control. Signing-key rotation is distinct from
changing the encryption secret. With the local derived fallback, changing the
application secret also changes the effective encryption secret unless the
previous master is supplied explicitly. The [legacy fallback transition](../README.md#configuration-and-request-boundaries)
explains recovery for older factory-override databases.

## PostgreSQL backup

Stop web and gateway first when preparing an upgrade/rollback snapshot so no
new identity/session changes are lost between the snapshot and migration.
Also finish or stop all operator jobs and other writers. PostgreSQL can remain
running; `pg_dump` makes a consistent database-native snapshot.

<!-- contract: postgres-backup -->
```bash
docker compose stop caddy web
umask 077
MINI_KEYCLOAK_BACKUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mini-keycloak-backup.XXXXXX")"
docker compose exec -T postgres pg_dump \
  --username=mini_keycloak --dbname=mini_keycloak --format=custom \
  > "$MINI_KEYCLOAK_BACKUP_DIR/database.dump"
```

Check the command's exit status before using the archive; a failed dump can
leave a partial file. Keep the directory path for recovery and move the archive
into your restricted backup store. Do not stream it to terminal output. The
command uses the container's local PostgreSQL socket, so no database password
appears in the command. This is a logical backup of `mini_keycloak`, not a copy
of the live PostgreSQL data directory or of cluster roles/global configuration.

Inspect archive readability without displaying row contents:

```bash
docker compose exec -T postgres pg_restore --list \
  < "$MINI_KEYCLOAK_BACKUP_DIR/database.dump" > /dev/null
```

That check cannot prove a successful restore. Record the application Git
revision/image ID, PostgreSQL major/image digest, migration revision, project
selection, and non-secret deployment settings alongside the backup. Keep the
matching application/key-encryption secrets separately under restricted access.
Caddy CA state is separate from a database dump; a recovery environment can generate
its own CA and explicitly trust its public root.

For local SQLite, use SQLite's online backup API/`.backup`, or stop all writers
before copying the database and required journal files. Confirm the actual
Flask instance path first; do not assume the database is in the shell working
directory. Copying only a live SQLite main file can miss journal/WAL state.

## Separate-environment restore validation

Test recovery in a separate isolated checkout/directory and Compose project,
with a fresh PostgreSQL volume. Copy configuration privately, preserve the
original application and key-encryption secrets, and select an unused loopback
HTTPS port plus an unused proxy subnet/address pair. Set an explicit unique
`COMPOSE_PROJECT_NAME` in that environment's `.env`; verify the new project has no
pre-existing containers/volumes before starting it. Use the original application
revision and compatible PostgreSQL major for the first restore attempt.

Within that separate restore environment, validate config, build the matching image,
start only PostgreSQL, and inspect health. Do not start migration/bootstrap/web
against the empty target before restoring:

```bash
docker compose config --quiet
docker compose build
docker compose up -d postgres
docker compose ps -a
```

Wait for PostgreSQL to be healthy. Set `MINI_KEYCLOAK_BACKUP_DIR` in this shell
to the private archive directory created above; the value is a filesystem path,
not a secret. Restore into the fresh empty `mini_keycloak` database:

<!-- contract: postgres-restore -->
```bash
docker compose exec -T postgres pg_restore \
  --username=mini_keycloak --dbname=mini_keycloak \
  --no-owner --no-privileges --single-transaction --exit-on-error \
  < "$MINI_KEYCLOAK_BACKUP_DIR/database.dump"
```

The single transaction avoids a partial committed restore. An occupied target
should fail: do not add `--clean` or drop an existing environment database to force it.
Resolve the target project and create a fresh recovery environment instead. The restored
database includes Alembic's revision; inspect it with the matching app image:

```bash
docker compose run --rm --no-deps migrate \
  flask --app mini_keycloak.app:create_app db current
docker compose up -d
docker compose ps -a
```

`up` now runs the explicit migration/bootstrap jobs before web as usual. With
the same application revision, an already-current schema stays unchanged and
bootstrap stays idempotent. Do not silently combine restore testing with an
application upgrade: use the separate upgrade procedure afterward.

Export the new environment's public CA and verify TLS discovery, private readiness,
expected realm/user/client identity, retained JWKS keys, and a new ordinary
S256 login/code exchange/refresh/userinfo/logout using disposable accounts.
Check [key metadata](#signing-key-rotation-and-retention) and audit events without
printing tokens, passwords, or private key material. A successful `pg_restore`
alone does not validate encrypted key usability or application behavior.

Older snapshots restore older credentials, enabled flags, session revocations,
refresh-consumption state, and throttle buckets. Artifacts revoked or consumed
after the snapshot can become usable again if still within their time bounds.
This is why recovery must stay isolated. A different restore origin prevents
old-token issuer validation; it does not prove those restored tokens are revoked.
If testing old token/session continuity is required, preserve the original
issuer only after stopping the original listener to avoid a port conflict.

After validation, target the recovery project's exact name/configuration for
teardown. `docker compose down` retains its volumes; `docker compose down --volumes`
deletes that recovery environment's database and CA. Remove its obsolete browser trust.
Do not delete the source backup or original environment while validating recovery.

## Upgrade and rollback preparation

Before changing a persistent environment, retain the old application image/revision,
configuration, matching secrets, and a verified pre-migration database backup.
Record migration status using the currently installed image. Complete a restore
rehearsal in a separate environment. Plan downtime and prevent concurrent CLI/import/key
jobs from writing while the upgrade runs.

With PostgreSQL healthy and the old deployment selected:

```bash
docker compose stop caddy web
docker compose run --rm --no-deps migrate \
  flask --app mini_keycloak.app:create_app db current
```

Take the [consistent backup](#postgresql-backup). Retain the previous application
image before building, because the `:local` tag is reused. Then select the
reviewed new checkout/configuration, keeping the same intended project, database
volume, and stable secrets. Validate and build it, then run migration/bootstrap
explicitly in order:

```bash
docker compose config --quiet
docker compose build
docker compose run --rm --no-deps migrate
docker compose run --rm --no-deps bootstrap
docker compose run --rm --no-deps migrate \
  flask --app mini_keycloak.app:create_app db current
docker compose up -d
docker compose ps -a
```

`up` may re-run the completed job services; repeated migration at head and
bootstrap are designed to be idempotent. Confirm jobs exit zero, readiness is
healthy, and TLS discovery plus an ordinary OIDC round trip work before resuming
environment use. Startup never substitutes for checking migration failures.

If migration or validation fails, keep web/gateway stopped. Check the generic
failure category and actual revision; do not force Alembic's version stamp.
Migration tests cover transactional rollback/retry, including normalized-identity
collisions. Correct invalid data only after reviewing a protected backup and
rehearsing the correction in a separate environment. Avoid blind retry loops.

Rollback means restoring the pre-migration database with the matching previous
application/configuration/secrets in a fresh isolated target. Pointing an old
image at a newer schema is not a rollback. Automated downgrade paths tested by
the project do not guarantee that destructive schema changes preserve every
future data shape. Database-major upgrades are a separate PostgreSQL maintenance
operation; replacing the pinned image over an incompatible data volume is not
supported by this runbook.

## Signing-key rotation and retention

Back up the database and preserve the encryption master first. For the bundled
realm, inspect metadata and rotate explicitly:

```bash
docker compose exec -T web flask --app mini_keycloak.app:create_app \
  realm-key-list --realm demo
docker compose exec -T web flask --app mini_keycloak.app:create_app \
  realm-key-rotate --realm demo
docker compose exec -T web flask --app mini_keycloak.app:create_app \
  realm-key-list --realm demo
```

The CLI prints only `kid`, algorithm, active/retained status, and timestamps.
It atomically installs one active encrypted RSA key, retaining prior public
verification keys in JWKS. New tokens use the new `kid`; old tokens remain
subject to their expiration, issuer/audience, and session checks. Unknown or
disabled realms fail without changing state. Concurrent rotation is tested
against live PostgreSQL.

Rotation does not revoke sessions/tokens and does not re-encrypt old keys under
a new master. There is no supported key deletion/pruning command or automatic
key-retention cleanup. Keep retained keys for existing-token verification; do
not manually delete database key rows as a routine operation. A changed master
cannot be repaired by assuming rotation will recover the previous ciphertext.

## Cleanup and session effects

Run cleanup with the same configuration/database as web:

```bash
docker compose exec -T web flask --app mini_keycloak.app:create_app \
  cleanup-expired --batch-size 100
```

The batch size is 1–1000, default 100. Each batch commits independently with a
fixed UTC cutoff and stable ordering; a later failure preserves completed
batches. Rerunning is safe. Schedule it externally; no background scheduler
is shipped, and expiry checks do not depend on cleanup running.

Cleanup deletes expired authentication sessions, unusable authorization codes,
expired/revoked refresh rows, idle/max-expired user sessions, and expired login
failure buckets. Dependencies and replacement links are handled before parents.
Revoked user-session rows stay until the first idle/max expiration so repeated
authenticated RP logout remains possible. Audit events remain, with a removed
session's nullable reference cleared. Realms/users/clients, credentials, signing
keys, live sessions/artifacts, and reset-mail records are retained. There is no
event or mail retention/deletion CLI; plan storage for retained environment data.

Ordinary refresh rotates tokens; reuse revokes the realm session and its refresh
families. Logout revokes the session and prevents subsequent refresh/userinfo.
Importing changed credentials or changing password policy does not automatically
revoke existing sessions, and reimport/bootstrap does not rotate an active key.
A web-only restart with stable database/secrets preserves sessions, keys,
cookies, and refresh state. Consumers that only verify an access JWT offline
can accept it until expiry without learning server-side session revocation;
server-side userinfo and refresh perform those session checks.

## Secret-safe troubleshooting

Start with `docker compose ps -a`, exit codes, private liveness/readiness, and
the TLS discovery check in [deployment](deployment.md#health-restart-and-teardown).
Read bounded logs locally:

```bash
docker compose logs --tail 50 web migrate bootstrap caddy
```

Application/Gunicorn JSON logs use fixed categories and a generated request ID.
Correlate the response `X-Request-ID` with `request_id` in those records. Incoming
request IDs are ignored. Query values, credentials, tokens, cookies, request
bodies, and response Location values are excluded. Caddy suppresses request
access/error logs, so a gateway-generated 404/502 may have no application ID.
Its startup diagnostics can still identify a certificate or listener problem.

| Symptom | Bounded checks |
| --- | --- |
| Configuration error naming a variable | Check its presence/type privately against the deployment tables; use `config --quiet`, never a resolved environment dump |
| PostgreSQL healthy, migration/bootstrap failed | Inspect one-shot job exit/logs and migration revision; do not start web manually around the dependency gate |
| Liveness 200, readiness 503 | Verify database availability, expected migration status, and original key-encryption secret; inspect key metadata with the configured CLI without exposing key bytes |
| Public health 404 | Expected Caddy boundary; run the private check inside web |
| Invalid Host 400 | Use `localhost` and the configured origin; the private probe needs `Host: localhost` |
| TLS verification failure | Export the current public root, use `--cacert`, and match hostname/port; a recreated CA needs renewed scoped trust |
| Gateway 502 | Check web status/private listener and readiness; do not enable raw proxy error dumps |
| Generic credential failure | Check enabled realm/client/user and ordinary throttle duration; preserve generic responses and do not inspect plaintext credentials |
| Database login fails after `.env` edit | Compare intended configuration privately with the existing database role; initializing environment variables does not rotate its stored password |

Do not troubleshoot by printing container environments, full SQL queries,
database URLs, import files, JWTs, reset links, or exception tracebacks. Avoid
`curl --verbose`/raw HTTP dumps around authentication. If sharing diagnostics,
share only non-secret version/revision, status/exit code, fixed event category,
and server-generated correlation ID after review. The local `outbox-list` CLI
prints recipients, so its output is still private operational data.
