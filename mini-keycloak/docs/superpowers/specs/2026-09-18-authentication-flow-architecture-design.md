# Authentication Flow Architecture Design

## Purpose

Replace the reset-specific state machine with a reusable authentication-flow
engine while preserving the public browser and OpenID Connect contracts. Add a
complete message-based credential-reset lifecycle, including signed action
tokens, an outbox, required actions, audit events, user-session creation, and
persisted authorization codes.

## Constraints

- Preserve the existing public realm, authorization, login-action, token, and
  required-action endpoint paths.
- Preserve the existing form field names used by browser clients.
- Preserve optimistic concurrency for authentication-session transitions.
- Keep reset responses uniform for unknown, disabled, and email-less users.
- Use ordinary identity-provider terminology throughout source, tests,
  templates, comments, and documentation.
- Do not add unrelated authentication mechanisms or administrative APIs.
- Keep the database-backed outbox as the delivery boundary; SMTP is outside
  this change.

## Domain Model

### Authentication flows

Each realm owns a reset-credentials flow. A flow has an opaque identifier, an
alias, and an ordered collection of executions. Each execution has an opaque
identifier, an authenticator provider identifier, a requirement, and a
priority. The initial realm flow contains these required executions:

1. Select the account.
2. Deliver reset instructions.
3. Update the password.

Realm bootstrap and realm import ensure that the flow and executions exist.
Runtime dispatch resolves executions from persisted configuration rather than
from semantic execution strings.

### Authentication sessions

Authentication sessions retain OIDC request data, the selected user, flow
identifier, execution statuses, and authentication notes. The current
execution is represented by an authentication note. Execution statuses record
successful and challenged executions so processing can resume across browser
requests.

### Reset messages

The database-backed outbox stores the recipient, related realm, client, user,
authentication session, token identifier, signed action token, token digest,
creation and expiry timestamps, and consumption timestamp. The CLI continues
to list message metadata without printing tokens or links.

Action tokens are signed JWTs containing a type, unique token identifier, user,
realm, client, authentication-session identifier, issued-at time, and expiry.
Signature, claim types, related records, expiry, and single-use state are all
validated before a flow is resumed.

## Components

### Authentication processor

`AuthenticationProcessor` loads the configured flow, exposes the current
session and user, dispatches browser actions, and completes successful flows.
It delegates execution traversal to `DefaultAuthenticationFlow` and delegates
account, message, credential, event, session, and protocol persistence to
existing repositories and services.

### Default authentication flow

`DefaultAuthenticationFlow` is independent of reset-specific behavior. It:

- traverses ordered executions;
- invokes authenticator `authenticate` and `action` methods;
- records success and challenge states;
- records the current execution for challenges and forks;
- renders an authentication-selection response when requested;
- resumes processing after successful actions; and
- returns a completed outcome when all required executions succeed.

Authenticators return typed results: `SUCCESS`, `CHALLENGE`, `FORK`, or
`FAILURE`. Browser rendering is performed outside the authenticators.

### Reset authenticators

The account-selection authenticator presents the identifier form and resolves
enabled users without changing the outward response for unsuccessful lookup.

The message authenticator recognizes a validated action-token user, otherwise
creates a reset message for eligible users and returns a fork result. Its
action phase completes the execution for the selected user.

The password authenticator presents the password form, validates the realm
password policy, updates the credential, records credential events, and returns
success.

### Action-token service

The action-token service issues signed tokens and persists their outbox
records. The action-token handler validates and atomically consumes a token,
loads the related authentication session, binds the token user to that session,
and resumes the configured flow.

### Browser completion

Successful completion creates a user session through `UserSessionService`,
issues a persisted authorization code through `AuthorizationService`, records
the login event, sets the browser session cookie, and redirects to the original
redirect URI with the original OIDC state.

## Request Flows

### Reset initiation

1. An authorization request creates an authentication session associated with
   the realm's configured reset flow.
2. Reset entry invokes the processor, which presents the account-selection
   execution.
3. Submitting an identifier completes account selection.
4. The message execution creates an outbox record for an eligible user and
   forks to the ordinary login page with a uniform status message.

### Action-token continuation

1. The action-token endpoint validates and consumes the token.
2. The token user and authentication session are bound together.
3. The processor resumes the configured flow.
4. The message execution completes and the password execution presents its
   form.
5. A valid password submission completes the flow and browser authentication.

### Authentication selection

A request to use another authentication method records selector state on the
authentication session and returns the selection page for the active
execution. Subsequent requests use the session's current execution when
rendering the selection response. Submitting an explicit selection clears the
selector state and dispatches the selected execution.

## Errors and Transactions

- Invalid realms, clients, sessions, executions, and tokens fail without
  disclosing account information.
- Unknown, disabled, and email-less accounts produce the same reset-initiation
  page and do not create deliverable messages.
- Expired, malformed, reused, or mismatched action tokens return a generic
  action error.
- Password-policy failures return the password form without completing the
  execution.
- Authentication-session and token consumption use optimistic or atomic
  concurrency so one transition wins and stale writers fail closed.
- A successful password update, user-session creation, authorization-code
  issuance, and associated audit events commit atomically.

## Events

The event system supports reset-message delivery and credential-update event
types. Reset delivery records the realm, client, user, authentication-session
correlation identifier, username, and email. Credential completion records the
password and credential updates under the same correlation identifier.

## Migration and Compatibility

An Alembic migration adds flow and execution tables, associates realms and
authentication sessions with flows, adds execution-status storage, and extends
reset-message metadata. Existing realms receive a default reset flow and
existing authentication sessions retain a valid initial execution during the
migration.

Compatibility properties may remain temporarily on the Python model where
existing callers need them, but runtime flow decisions use configured
executions, status maps, and authentication notes.

## Testing

Tests are written before production changes and cover:

- flow traversal and typed result handling;
- opaque execution lookup and selector handling;
- account lookup response uniformity;
- reset-message creation and metadata privacy;
- valid, expired, malformed, mismatched, and reused action tokens;
- action-token flow continuation;
- password-policy rejection and successful credential update;
- reset and credential event correlation;
- real user-session and authorization-code creation;
- original OIDC state preservation;
- optimistic-concurrency behavior;
- SQLite migrations and PostgreSQL behavior where configured; and
- the existing public endpoint and form contracts.

The complete existing test suite remains the regression gate.
