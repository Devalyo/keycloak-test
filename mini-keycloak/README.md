# Mini Keycloak OIDC provider

Follow the [repository setup](../README.md) to migrate and bootstrap the local
SQLite database. Migrations and bootstrap are explicit CLI operations. Signing
keys, credentials, protocol artifacts, and sessions persist across restarts.
The [deployment guide](docs/deployment.md) covers the shipped PostgreSQL,
Gunicorn, and Caddy TLS stack and the complete environment reference. The
[operations runbook](docs/operations.md) covers backup/restore, upgrades,
secret stability, key rotation, cleanup, and diagnostics. These guides describe
this compact implementation and do not promise full Keycloak compatibility.

## Discovery and endpoints

With the default external URL, read
`http://127.0.0.1:5000/realms/demo/.well-known/openid-configuration`.
The issuer and advertised endpoints come from trusted configuration (or the
realm issuer override), never the request Host or forwarded headers.

| Method | Path under `/realms/{realm}` | Purpose |
| --- | --- | --- |
| GET | `/.well-known/openid-configuration` | Implemented capabilities and endpoints |
| GET | `/protocol/openid-connect/certs` | Public RSA keys, including retained keys |
| GET | `/protocol/openid-connect/auth` | Browser authorization code flow |
| POST | `/login-actions/authenticate` | Bound browser login form |
| POST | `/protocol/openid-connect/token` | Code exchange, refresh, enabled password grants |
| GET, POST | `/protocol/openid-connect/userinfo` | Claims authorized by an access token |
| GET, POST | `/protocol/openid-connect/logout` | RP logout; POST also supports legacy refresh logout |

Only RS256, response type `code`, S256 PKCE, and the scopes `openid`, `profile`,
and `email` are supported. Implicit flow, dynamic registration, roles, MFA, and
prompt/max_age options are not implemented.

## Browser code flow with PKCE

Use a standard OIDC client library. Generate a cryptographically random verifier
of 43–128 permitted PKCE characters and derive
`BASE64URL(SHA256(verifier))` without padding. Keep the verifier in the client.
Navigate the browser to the authorization endpoint with `client_id`, an exactly
registered `redirect_uri`, `response_type=code`, `scope=openid profile email`,
unpredictable `state`, `nonce`, `code_challenge`, and `code_challenge_method=S256`.

The server creates a short-lived login transaction and a separate HttpOnly,
SameSite=Lax pre-authentication cookie for each tab. Submit the form in that
browser. Successful login returns `code` and the opaque original `state`; the
client must check state. An eligible realm SSO cookie can reuse the session.
New client registrations default to mandatory S256. The bundled environment client has
an explicit optional policy, but ordinary clients should send S256 regardless.

POST URL-encoded form fields to the token endpoint:

```text
grant_type=authorization_code
client_id=<registered public client>
code=<returned single-use code>
redirect_uri=<exact original URI>
code_verifier=<original verifier>
```

Public clients use `client_id` without a secret. Confidential clients use exactly
one authentication method: HTTP Basic (`client_secret_basic`, with form-encoded
ID/secret before Base64) or `client_id` plus `client_secret` form fields. Never
mix credential sources. Codes are hashed at rest, expire, and can be consumed
once. Issuance and consumption commit with their dependent session/token state.

The response contains Bearer access, ID, and tracked refresh tokens (ID tokens
require `openid`), scope, lifetimes, and `session_state`. Validate ID-token
signature against the realm JWKS, pin RS256, and check issuer, audience, expiry,
and nonce using the OIDC library. Access tokens are for the intended audience;
an ID or refresh token cannot be used as a userinfo bearer credential.

## Refresh, userinfo, and logout

Refresh by posting `grant_type=refresh_token`, `refresh_token`, and client
authentication. Optional `scope` can narrow the original grant. Every refresh
rotates the token; replace the stored token atomically. Reusing a consumed token
revokes its realm session and all associated refresh families. Do not retry an
old refresh token after receiving a replacement. Expired/revoked sessions and
disabled realm, client, or user state fail closed.

Call userinfo with `Authorization: Bearer <access_token>`. POST also accepts
one `access_token` in a URL-encoded body. Never send it in a query string or
combine sources. The response always includes `sub`; `profile` adds
`preferred_username`, and `email` adds `email` and `email_verified`.

RP logout takes an `id_token_hint`, optional matching `client_id`, an exactly
registered `post_logout_redirect_uri`, and opaque `state`. A missing or
unregistered destination produces a local response. A cryptographically valid
expired ID hint can identify its retained session within that session's idle
and maximum lifetime; this exception applies only to logout. Retried logout is
idempotent within those bounds, including after cleanup. Revoked session rows
remain until the first idle/max expiration, without extending either bound.
Logout clears the realm browser cookie after
committing revocation and prevents subsequent refresh/userinfo. Legacy POST
logout accepts client authentication plus a current `refresh_token`.

Password grants additionally require both realm and client opt-in, an enabled
user, and valid credentials. They issue the same tracked token set and return
the same public failure for an unknown user and a wrong password.

## Realm JSON import

The local CLI accepts the subset below of Keycloak 26.7.1-style realm JSON.
It is not a complete Keycloak export importer or an administration API. From
this directory, with the database configuration used by the server:

```bash
../.venv/bin/python -m flask --app mini_keycloak.app db upgrade
../.venv/bin/python -m flask --app mini_keycloak.app realm-import tests/fixtures/realm-import/valid-realm.json
../.venv/bin/python -m flask --app mini_keycloak.app realm-import /absolute/path/to/realm-update.json --update
```

The [valid fixture](tests/fixtures/realm-import/valid-realm.json) creates realm
`example`, a public `example-browser` client with mandatory S256, and a local
example user. Its published password is disposable test data. The
[invalid fixture](tests/fixtures/realm-import/invalid-secrets.json) demonstrates
rejection of a public-client secret and a temporary password; importing it
must fail without creating any rows. Store private import files with restricted
permissions; do not put real passwords or client secrets in command arguments,
version control, metadata, or diagnostic field names.

The complete document is validated before database mutation. One realm's
clients, users, password hashes, and encrypted signing key commit together.
Validation, hashing, encryption, database, and commit failures roll back the
operation, including changes already flushed. Public diagnostics use fixed
categories and field paths without submitted values or driver details. Imports
do not create audit events. Passwords and client secrets are hashed before
storage; DTO representations omit them, and temporary import references are
released before rendering failures. This is reference cleanup, not guaranteed
erasure of Python process memory.

### Supported fields

JSON booleans must be booleans, lifetimes must be integers, and collections must
have the listed types. Names are trimmed for import and compared using Unicode
casefold; existing identifier spelling and internal IDs remain stable. Usernames,
client IDs, and nonempty emails must be unique within a realm after normalization.
Realm names must be ASCII path segments beginning with a letter or digit, followed
by letters, digits, `.`, `_`, or `-`, with no `..` sequence.

| Object | Accepted fields and behavior |
| --- | --- |
| Realm identity | `realm` (required); `displayName` (nullable string); `enabled` (default `true`); `resetPasswordAllowed` (boolean, default `true`) |
| Realm lifetimes | `accessTokenLifespan`, `accessCodeLifespan`, `ssoSessionIdleTimeout`, `ssoSessionMaxLifespan`: seconds, 1–2,147,483,647; omitted values use configured defaults |
| Realm policy | `passwordPolicy`: raw policy string plus parsed known clauses; empty string clears the imported policy |
| Realm collections | `clients`, `users`: arrays; `attributes`: string-valued object supporting only `mini.keycloak.passwordGrantEnabled` with string `"true"` or `"false"` (default `"false"`) |
| Client identity/access | `clientId` (required); `name` (nullable); `enabled` (default `true`); `publicClient` (default `true`); `secret` (nonempty string, required for new confidential clients, forbidden for public clients) |
| Client destinations | `redirectUris`, `webOrigins`: string arrays, default empty; exact URI restrictions below |
| Client flows/scopes | `standardFlowEnabled` (default `true`), `directAccessGrantsEnabled` (default `false`); `defaultClientScopes` (default `openid`, `profile`, `email`), `optionalClientScopes` (default empty); only those three scope names are supported |
| Client attributes | String-valued `attributes` supports `pkce.code.challenge.method`: `S256` (default) or `optional`; and `post.logout.redirect.uris`: exact URIs separated by `##`, or empty to clear |
| User identity/profile | `username` (required), `email` (nullable), `enabled` (default `true`), `emailVerified` (default `false`), `firstName`, `lastName` (nullable strings) |
| User attributes | `attributes`: arbitrary bounded names mapped to arrays of strings, default empty object; stored as profile data, not automatically emitted as token claims |
| User credentials | `credentials`: empty array or one object with `type: "password"`, nonempty plaintext `value`, and optional `temporary: false`; omission/empty array creates no new password and preserves an existing one |

Unknown realm/client/user fields and unsupported realm/client attributes produce
sorted, path-qualified warnings and are ignored. Unsupported attribute values
still must be strings. Unknown credential fields, hashed/algorithm-specific
credentials, other credential types, and temporary passwords are errors. Internal
`id`, `realmId`, roles, groups, protocol mappers, federation, required actions,
issuer overrides, and other unlisted export features are not imported. IDs in
JSON cannot select or move another realm's records. Review all warnings: ignored
configuration is not an implemented security policy.

Password policies support `length(n)`, `digits(n)`, `lowerCase(n)`,
`upperCase(n)`, and `specialChars(n)`, joined by ` and `; duplicate known clauses
are errors. Minimum length is 1–4096; the other minima are 0–4096. Syntactically
valid unknown clauses warn and are not enforced; malformed clauses fail.
Each newly supplied import password is checked before hashing against the final
effective policy, including an existing policy omitted from an update. Length
counts Unicode characters; digit/case checks use Unicode character properties;
special characters are non-alphanumeric characters. Existing omitted passwords
are not rechecked or changed when policy changes. The raw policy and recognized
clauses are stored. The evaluator protects imported credentials, repository
password creation/replacement, and replacement passwords submitted through reset
required actions. A weak replacement fails before credential or flow-state
mutation.

Browser login and enabled password grants share persistent failure
buckets derived from realm, normalized submitted identifier, and validated source
address using an application-secret HMAC. The defaults are five failures within
300 seconds followed by a fixed 60-second block; attempts during the block do
not extend it. Successful authentication clears that bucket. Unknown-user,
wrong-password, and blocked responses remain generic. Its
[configuration](docs/deployment.md#application-configuration) and secret-change
effects are documented in the operator guides.

### Exact URI subset and limits

Redirect and post-logout URLs must be absolute HTTP(S) URIs. Accepted authorities
are ASCII DNS names (including localhost and punycode), canonical dotted-decimal
IPv4, or bracketed IPv6, optionally followed by a decimal port from 0 through
65535 with no leading zeros. Paths and queries use ASCII URI characters and
well-formed percent escapes. Accepted spelling is preserved and registration
matching remains exact; equivalent-looking case or port spellings are not
rewritten. Web origins allow only scheme and authority, with no path (including
a trailing slash) or query; the Keycloak `+` marker is also accepted.

Credentials in authority, fragments (even empty `#`), wildcards, backslashes,
whitespace/control characters, malformed escapes, and literal or percent-encoded
`.`/`..` path segments are rejected. This application deliberately also excludes
some generally valid URI spellings: trailing-dot DNS names, zero-padded ports,
raw Unicode hosts/paths, IPv6 zone identifiers, and IPvFuture. Use punycode hosts
and percent-encoded paths where needed. Short, hexadecimal, and octal IPv4
spellings are excluded. PKCE `plain` is never supported; an optional-PKCE client
must still validate any supplied S256 pair.

| Budget | Limit |
| --- | --- |
| File | One UTF-8 JSON object, at most 2 MiB; a sentinel byte detects overflow before decoding |
| Structure, including ignored fields | Maximum depth 16 (root depth 0), 50,000 values, and a 2 MiB decoded-size estimate; duplicate keys and non-finite numbers fail |
| Entities | At most 1,000 clients and 1,000 users per document |
| String lists | At most 256 entries (redirects, origins, logout URIs, scopes) |
| Attribute objects | At most 64 entries; each user attribute has at most 64 string values |
| Strings | Identifiers/profile names/object keys 255 characters; email 320; URI/user attribute values 2048; secrets, raw policies, realm/client attribute values 4096 |
| Character validity | C0/C1 control characters, DEL, and unpaired Unicode surrogates fail even in ignored data |

### Updates and bundled bootstrap

By default, importing an existing normalized realm name fails. `--update`
explicitly upserts listed clients/users and updates only supplied fields.
Unlisted entities, sessions, keys, and omitted fields remain. Supplied lists
replace that field's list; user `attributes` replaces that user's attribute
object. Supported realm/client attribute entries update independently. Explicit
`false`, empty lists/objects, and nullable fields take effect; empty entity lists
do not delete entities. Updating a missing realm creates it. There is no
replace/delete mode, realm rename, or export command.

Omitted passwords/secrets stay unchanged. A supplied password or confidential
secret rotates only that credential; converting a client to public clears its
secret. Existing confidential clients may omit a secret only when one already
exists. Importing does not revoke existing sessions or rotate an active key.
Success counts describe clients/users listed in the document, not total rows.
In-process callers must provide a clean session with no pending new, dirty, or
deleted objects; importer failure rolls back the caller's entire transaction.

`bootstrap-demo` loads a packaged fixture independent of the current working
directory. It creates missing bundled data and is idempotent: repeated runs
preserve operator metadata, identifiers, passwords/secrets (including deliberate
absence), active key, sessions, and unrelated data. Newly created entities get
their fixture credentials. Only the bundled realm/client compatibility policies
are normalized. Generic imports default to mandatory S256.

## Signing-key operations and backups

```bash
../.venv/bin/python -m flask --app mini_keycloak.app realm-key-list --realm example
../.venv/bin/python -m flask --app mini_keycloak.app realm-key-rotate --realm example
```

Listing reports only `kid`, algorithm, active/retained status, and creation,
activation, and deactivation timestamps. Unknown or disabled realms fail with
a concise error. Rotation generates and encrypts a new RSA key, atomically
activates it, and retains older keys. New tokens use the new `kid`; old tokens
still verify against retained JWKS keys subject to normal expiration and session
checks. Rotation does not re-encrypt old keys or revoke tokens. No key deletion
command or automatic key-retention cleanup is provided. Reimport/bootstrap does
not rotate an existing active key. SQLite serialization and live PostgreSQL
concurrent rotation are covered by the implemented test gates.

Before updates, migrations, or rotation, take a consistent database backup and
securely preserve the matching key-encryption master secret and application
configuration separately. Use SQLite's backup API/`.backup` command, or stop all
writers before copying a database and its required journal files. Relative SQLite
URLs resolve under Flask's instance directory; confirm the actual configured
path before backing up. For PostgreSQL, use a consistent database-native backup.
Protect both source JSON and backups, which contain private identity/session data
and encrypted keys; do not log their contents or the encryption secret. Test
restore on a separate isolated database with the original encryption secret.
Restoring an older snapshot can restore older credential/session state. Changing
the master secret alone makes existing private keys unusable; key rotation is
not a master-secret migration. See the explicit transition guidance below.

## Configuration and request boundaries

This table summarizes local defaults. The complete application, PostgreSQL pool,
proxy, throttle, Gunicorn, and Compose environment reference is in
[deployment configuration](docs/deployment.md#application-configuration).
The `production` profile requires PostgreSQL/psycopg, HTTPS, secure cookies,
explicit Host/proxy configuration, and independent application/key secrets.

| Environment variable | Local default |
| --- | --- |
| `MINI_KEYCLOAK_DATABASE_URL` | `sqlite:///mini-keycloak.db` |
| `MINI_KEYCLOAK_EXTERNAL_URL` | `http://127.0.0.1:5000` |
| `MINI_KEYCLOAK_SECRET_KEY` | Local development fallback; supply a private random value |
| `MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET` | Local derivation from the application secret |
| `MINI_KEYCLOAK_SESSION_COOKIE_SECURE` | `false` for local HTTP; set `true` for HTTPS |
| `MINI_KEYCLOAK_ACCESS_TOKEN_LIFETIME_SECONDS` | `300` |
| `MINI_KEYCLOAK_AUTHORIZATION_CODE_LIFETIME_SECONDS` | `60` |
| `MINI_KEYCLOAK_REFRESH_TOKEN_LIFETIME_SECONDS` | `1800` |
| `MINI_KEYCLOAK_SSO_IDLE_LIFETIME_SECONDS` | `1800` |
| `MINI_KEYCLOAK_SSO_MAX_LIFETIME_SECONDS` | `36000` |

Positive realm lifetime overrides take precedence. Preserve the key-encryption
secret across restarts; replacing it does not re-encrypt existing signing keys.
The local fallback is derived from the final application `SECRET_KEY`, including
factory overrides. An explicit `OIDC_KEY_ENCRYPTION_SECRET` factory value takes
precedence over the environment master secret; either explicit source takes
precedence over the fallback. Empty master secrets are rejected.

Existing databases created with a factory `SECRET_KEY` override and no explicit
master secret need an explicit transition: older versions derived their master
secret from the environment application secret (or the public local default),
ignoring the factory override. Back up that database and supply that previous
master secret explicitly before restarting. Its value can be computed in-process
with `Settings(secret_key=previous_environment_secret).as_flask_config()["OIDC_KEY_ENCRYPTION_SECRET"]`,
where `previous_environment_secret` is the old `MINI_KEYCLOAK_SECRET_KEY`, or
`local-development-secret-change-me` if it was unset. Pass the result as the explicit
master secret without printing or logging it. Existing signing keys are never
silently replaced or re-encrypted; a wrong master secret fails token issuance
closed. Keep the explicit master stable when changing the application secret.

Passwords/client secrets use Argon2 hashes; private signing keys are encrypted
at rest. Public JWKS never includes private key material.

Ordinary OIDC/browser requests are limited to 64 KiB bodies and 64 multipart
parts. Oversized input returns a generic 413 (OAuth JSON for OIDC endpoints,
HTML for browser login). Authentication pages are escaped, no-store, protected
by CSP/frame denial, and use a no-referrer policy. Protocol responses are
no-store and nosniff. Expected failures omit submitted identities and secrets;
unexpected failures roll back and return generic errors without exception text.

For ordinary authenticate POST only, a supplied `Origin` must match the effective
realm issuer's canonical scheme, host, and port. A realm issuer override takes
precedence; otherwise `MINI_KEYCLOAK_EXTERNAL_URL` supplies the origin. Issuer
paths do not participate in this comparison; host case and HTTP/HTTPS default
ports are normalized. When a realm has an override, the global origin does not
remain allowed unless it represents the same canonical origin.
`null`, malformed, and foreign origins are rejected. A supplied `Sec-Fetch-Site`
must be `same-origin`; `same-site` and `cross-site` are rejected too. If both
headers are supplied both must pass. Clients omitting both remain supported,
including non-browser integration tests; they still need the per-transaction
pre-auth cookie. Configure the external URL to the URL actually used by the
browser. Host and forwarded headers cannot override this policy. These checks
and body limits are scoped to ordinary routes and do not modify reset actions.

## Audit events and cleanup

`security_events` records ordinary login success/failure, code exchange,
password grants, refresh/refresh-reuse, and authenticated logout. Failed
protocol operations record an error event after rollback; success events commit
with the operation. Reuse events commit with defensive revocation; an isolated
audit-write failure is logged without undoing that revocation. Unknown
realms have no event row because events require a real realm foreign key.

The event service accepts only known event/error types, validated same-realm
database identifiers, a parsed source IP address authorized by the direct-peer
proxy boundary, and finite allowed values
for `grant_type`, `auth_method`, and `reason`. Values are bounded; arbitrary
detail keys, nested data, and free text are dropped. Passwords, submitted
usernames, secrets, code/token values or hashes, cookies, keys, state/nonce,
and reset links are never copied into events. Failure-audit storage outages
produce a generic log message. Every application factory installs one idempotent
Werkzeug logging filter, covering the documented local server and Flask's server.
It omits the entire query from request-line/URL log arguments, including unknown,
repeated, encoded, and future parameters. Ordinary access records retain method,
path, and status. Werkzeug error diagnostics use a fixed message because malformed
HTTP parsing errors can otherwise quote isolated query values. The filter changes
logs only, not request data. Application failure logs omit submitted values.

The shipped Gunicorn runtime emits JSON access records with method, path, status,
size, duration, source address, and a server-generated `X-Request-ID`. Application
and Gunicorn error logs use fixed JSON events without exception details. Incoming
request IDs are never trusted. Query values, sensitive headers, bodies, and
response `Location` values are omitted. Caddy suppresses request access/error
logs; its runtime diagnostics remain available. The Werkzeug filter does not
protect arbitrary replacement servers or proxies. RP callback logs need the
same no-query policy because authorization codes arrive at the RP in a query.

From this directory, using the same database configuration:

```bash
../.venv/bin/python -m flask --app mini_keycloak.app cleanup-expired --batch-size 100
```

The batch size accepts 1–1000 (default 100). Cleanup uses one UTC cutoff and
stable primary-key ordering, committing each batch and printing counts per
table. It deletes expired authentication sessions and codes, expired/revoked
refresh rows, and idle/max-expired user sessions. Unusable code/refresh children
of revoked sessions can be removed immediately, but the revoked session remains
through its idle/max retention window so repeated authenticated RP logout still
succeeds. Dependencies are removed before expired sessions. It clears replacement
links before deleting referenced refresh rows. Audit events are retained; their
nullable session reference is cleared before that session is removed. Live
sessions/artifacts, realms, users, clients, signing keys, and reset mail remain.
Expired ordinary-login failure buckets are deleted too.
Schedule this command externally. Re-running it is safe; expiry enforcement
does not depend on cleanup. Completed batches remain committed if a later
batch fails. See [operations](docs/operations.md#cleanup-and-session-effects)
for the container command and retention consequences.

## Tests

From this directory, run tests without live infrastructure gates:

```bash
../.venv/bin/python -m pytest tests \
  --ignore=tests/postgres --ignore=tests/deployment -q
```

## Implemented scope and non-goals

Persistent realms, normalized clients/users, Argon2 credentials, encrypted RSA
signing keys, browser authentication/SSO, ordinary OIDC grants, tracked sessions,
bounded atomic realm import, idempotent bootstrap, policy enforcement,
ordinary-login throttling, audit events, and expiry cleanup are implemented.
PostgreSQL migrations/concurrency, JSON logs, strict request boundaries, private
health probes, and the loopback TLS deployment have integration coverage.

There is no administration UI/API, complete Keycloak export compatibility,
federation, roles/groups, protocol mappers, MFA, dynamic client registration,
implicit flow, upstream SMTP delivery, automatic key pruning, master-secret
re-encryption, background cleanup scheduler, or high-availability guarantee.
