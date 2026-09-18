# Authentication Flow Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the reset-specific state machine with a configurable authentication-flow engine and a complete database-backed credential-reset lifecycle.

**Architecture:** Persist realm flows and opaque executions, dispatch them through a generic processor, and implement account selection, message delivery, and password update as independent authenticators. Signed single-use action tokens resume the same authentication session, and successful completion uses the existing user-session and authorization-code services.

**Tech Stack:** Python 3.10+, Flask 3.1, SQLAlchemy 2, Alembic, PyJWT, pytest

**Spec:** `docs/superpowers/specs/2026-09-18-authentication-flow-architecture-design.md`

## Global Constraints

- Preserve existing public endpoint paths and browser form field names.
- Preserve optimistic concurrency for authentication sessions.
- Keep account lookup responses uniform.
- Use a database-backed message outbox; do not add SMTP.
- Do not expose action tokens through CLI output or application logs.
- Use ordinary identity-provider terminology in source, tests, templates, comments, and documentation.
- Do not add unrelated administrative APIs or authentication mechanisms.
- Every production change follows a failing test.
- Each task receives at most two review passes: specification compliance and code quality.

---

## File Structure

### New files

- `mini_keycloak/authentication/constants.py`: shared authentication-session note names and provider identifiers.
- `mini_keycloak/authentication/engine.py`: typed results, authenticator context, registry, and generic flow traversal.
- `mini_keycloak/authentication/processor.py`: session-bound flow dispatch and completion boundary.
- `mini_keycloak/reset_credentials/authenticators.py`: account, message, and password authenticators.
- `mini_keycloak/services/action_tokens.py`: signed token issuance, validation, and atomic consumption.
- `mini_keycloak/services/authentication_flows.py`: default realm-flow provisioning and execution lookup.
- `migrations/versions/0007_authentication_flows.py`: flow, execution, session, and outbox schema transition.
- `tests/test_authentication_flow_engine.py`: generic engine unit tests.
- `tests/test_reset_action_tokens.py`: token and outbox service tests.
- `tests/test_reset_credentials_browser_flow.py`: browser integration and completion tests.

### Modified files

- `mini_keycloak/models/identity.py`: realm reset-flow association.
- `mini_keycloak/models/authentication.py`: flow, execution, session-status, and message metadata.
- `mini_keycloak/models/__init__.py`: model exports.
- `mini_keycloak/repositories/authentication.py`: flow/session/message queries and atomic token consumption.
- `mini_keycloak/store.py`: compatibility facade over the new repositories and services.
- `mini_keycloak/services/bootstrap.py`: default flow provisioning.
- `mini_keycloak/services/realm_import.py`: flow provisioning for imported realms.
- `mini_keycloak/services/authorization.py`: accept processor-completed authentication sessions.
- `mini_keycloak/services/events.py`: reset and credential event types and trusted detail projection.
- `mini_keycloak/authentication/browser.py`: initialize sessions with configured flows.
- `mini_keycloak/app.py`: route requests through the processor and add action-token continuation.
- `mini_keycloak/reset_credentials/flow.py`: compatibility imports only after callers migrate.
- Existing reset, authorization-code, concurrency, event, import, bootstrap, and migration tests.

---

### Task 1: Persist Configured Authentication Flows

**Files:**
- Create: `mini_keycloak/services/authentication_flows.py`
- Create: `migrations/versions/0007_authentication_flows.py`
- Modify: `mini_keycloak/models/identity.py`
- Modify: `mini_keycloak/models/authentication.py`
- Modify: `mini_keycloak/models/__init__.py`
- Modify: `mini_keycloak/repositories/authentication.py`
- Modify: `mini_keycloak/services/bootstrap.py`
- Modify: `mini_keycloak/services/realm_import.py`
- Test: `tests/test_migrations.py`
- Test: `tests/test_realm_import_service.py`
- Test: `tests/test_bundled_realm_fixture.py`

**Interfaces:**
- Produces: `AuthenticationFlow`, `AuthenticationExecution`, and `AuthenticationFlowService`.
- Produces: `AuthenticationFlowService.ensure_reset_flow(realm: Realm) -> AuthenticationFlow`.
- Produces: `AuthenticationFlowService.executions(flow_id: str) -> tuple[AuthenticationExecution, ...]`.
- Produces provider IDs `reset-credentials-choose-user`, `reset-credential-email`, and `reset-password`.

- [ ] **Step 1: Write failing model and provisioning tests**

Create or import a realm and assert that `ensure_reset_flow()` binds one flow with three opaque, ordered, required executions using the provider IDs above. Assert a second call reuses the same rows without modifying operator-owned realm data.

- [ ] **Step 2: Run focused tests and verify the missing-model failure**

```bash
pytest -q tests/test_realm_import_service.py tests/test_bundled_realm_fixture.py
```

Expected: collection or assertion failure because the flow models and service do not exist.

- [ ] **Step 3: Add flow models and repository operations**

Implement persisted `AuthenticationFlow(id, realm_id, alias, provider_id, built_in)` and `AuthenticationExecution(id, flow_id, authenticator, requirement, priority)`. Add `Realm.reset_credentials_flow_id`, `AuthenticationSession.flow_id`, and mutable JSON `execution_status`. Add repository methods that resolve flows and ordered executions by realm and identifier.

- [ ] **Step 4: Provision default flows during realm creation and import**

Implement `AuthenticationFlowService.ensure_reset_flow()` so it creates exactly one built-in flow and three required executions, flushes them, and binds the realm. Call it from realm import and demo bootstrap without rewriting an existing binding.

- [ ] **Step 5: Write failing migration assertions**

Extend `tests/test_migrations.py` to require revision `0007`, both new tables, all new columns, one bound flow and three executions per existing realm, retained existing rows, reversible downgrade, and clean `compare_metadata()` output.

- [ ] **Step 6: Run migration tests and verify revision/schema failure**

```bash
pytest -q tests/test_migrations.py
```

Expected: failure because revision `0007` and the schema are absent.

- [ ] **Step 7: Implement migration `0007`**

Create the tables and columns, seed one flow and three opaque executions per existing realm, bind existing sessions to their realm flow, and translate existing session execution values into corresponding execution identifiers and authentication notes. Downgrade restores semantic session values and the pre-`0007` schema.

- [ ] **Step 8: Run focused persistence and migration tests**

```bash
pytest -q tests/test_migrations.py tests/test_realm_import_service.py tests/test_bundled_realm_fixture.py
```

Expected: all pass.

- [ ] **Step 9: Commit Task 1**

```bash
git add mini_keycloak/models mini_keycloak/repositories/authentication.py mini_keycloak/services/authentication_flows.py mini_keycloak/services/bootstrap.py mini_keycloak/services/realm_import.py migrations/versions/0007_authentication_flows.py tests/test_migrations.py tests/test_realm_import_service.py tests/test_bundled_realm_fixture.py
git commit -m "feat: persist configurable authentication flows"
```

---

### Task 2: Add the Generic Authentication Engine

**Files:**
- Create: `mini_keycloak/authentication/constants.py`
- Create: `mini_keycloak/authentication/engine.py`
- Create: `mini_keycloak/authentication/processor.py`
- Create: `tests/test_authentication_flow_engine.py`
- Modify: `mini_keycloak/authentication/__init__.py`
- Modify: `mini_keycloak/repositories/authentication.py`

**Interfaces:**
- Consumes: persisted flows and executions from Task 1.
- Produces: `FlowStatus`, `AuthenticatorResult`, `FlowOutcome`, `AuthenticatorContext`, `AuthenticatorRegistry`, `DefaultAuthenticationFlow`, and `AuthenticationProcessor`.
- Produces: `AuthenticationProcessor.process_flow() -> FlowOutcome`.
- Produces: `AuthenticationProcessor.process_action(execution_id: str, form: Mapping[str, str]) -> FlowOutcome`.

- [ ] **Step 1: Write failing engine traversal tests**

Use database-backed recording authenticators. Assert that a challenge records its opaque current execution, a successful action records `SUCCESS` and advances, completed executions are skipped, `FORK` records its execution, unknown execution IDs fail, and completion occurs only after every required execution succeeds.

- [ ] **Step 2: Run engine tests and verify missing-interface failure**

```bash
pytest -q tests/test_authentication_flow_engine.py
```

Expected: collection failure because the engine interfaces do not exist.

- [ ] **Step 3: Implement typed results and registry**

Implement `FlowStatus` values `SUCCESS`, `CHALLENGE`, `FORK`, and `FAILURE`; immutable `AuthenticatorResult(status, page, message, error)`; and immutable `FlowOutcome(page, execution_id, message, complete)`. Map persisted provider IDs to authenticator objects exposing `authenticate(context)` and `action(context, form)`.

- [ ] **Step 4: Implement traversal, action dispatch, selection state, and fork handling**

Load executions by priority, skip successful entries, record challenged/current executions, and continue after successful actions. A `tryAnotherWay` action records selector state and returns the selection page. An explicit `authenticationExecution` clears selector state and must belong to the configured flow.

- [ ] **Step 5: Implement the processor boundary**

Validate the session's realm, client, configured flow, selected user, and requested execution before delegating. Return typed completion without issuing protocol artifacts.

- [ ] **Step 6: Run engine and concurrency tests**

```bash
pytest -q tests/test_authentication_flow_engine.py tests/test_authentication_session_concurrency.py
```

Expected: all pass.

- [ ] **Step 7: Commit Task 2**

```bash
git add mini_keycloak/authentication mini_keycloak/repositories/authentication.py tests/test_authentication_flow_engine.py tests/test_authentication_session_concurrency.py
git commit -m "feat: add authentication flow processor"
```

---

### Task 3: Add Reset Authenticators and Action Tokens

**Files:**
- Create: `mini_keycloak/reset_credentials/authenticators.py`
- Create: `mini_keycloak/services/action_tokens.py`
- Create: `tests/test_reset_action_tokens.py`
- Modify: `mini_keycloak/models/authentication.py`
- Modify: `mini_keycloak/repositories/authentication.py`
- Modify: `mini_keycloak/services/events.py`
- Modify: `mini_keycloak/store.py`

**Interfaces:**
- Consumes: engine authenticator interfaces from Task 2.
- Produces: `ResetActionTokenService.issue(session, user) -> ResetEmail`.
- Produces: `ResetActionTokenService.consume(realm_name: str, raw_token: str) -> tuple[AuthenticationSession, User]`.
- Produces: `ResetCredentialChooseUser`, `ResetCredentialEmail`, and `ResetPassword`.

- [ ] **Step 1: Write failing token issuance tests**

Assert that issuance creates one row with realm, client, user, authentication session, token ID, signed token, SHA-256 digest, and expiry. Assert CLI output omits the signed token and digest.

- [ ] **Step 2: Write failing validation and concurrency tests**

Cover valid consumption, invalid signature, wrong realm, mismatched client/session/user claims, expiry, repeat use, and two concurrent consumers with one winner. Rejections must not consume the row unless another transaction won.

- [ ] **Step 3: Run token tests and verify missing-service failure**

```bash
pytest -q tests/test_reset_action_tokens.py
```

Expected: collection failure because the token service does not exist.

- [ ] **Step 4: Implement signed issuance and atomic consumption**

Issue HS256 JWTs with exact claims `typ`, `jti`, `sub`, `realm_id`, `client_id`, `asid`, `iat`, and `exp`. Validate algorithm and claim types, compare the persisted digest with `hmac.compare_digest`, verify every related record, and atomically set `consumed_at` only when null and unexpired.

- [ ] **Step 5: Write failing authenticator tests**

Cover identifier challenge, enabled-user selection, uniform unsuccessful lookup, message creation, fork outcome, token continuation, password challenge, policy rejection, password update, and execution-status changes using real repositories.

- [ ] **Step 6: Run authenticator tests and verify missing-provider failure**

```bash
pytest -q tests/test_reset_action_tokens.py -k authenticator
```

Expected: failure because the providers do not exist.

- [ ] **Step 7: Implement authenticator providers**

The choose-user provider records the attempted username and selected enabled user, then succeeds. The email provider creates a message and forks during authentication, recognizes the validated token-user note during continuation, and completes its action for a selected user. The password provider validates matching fields and realm policy, updates the credential, records credential events, and succeeds.

- [ ] **Step 8: Extend trusted event projection**

Add `SEND_RESET_PASSWORD`, `UPDATE_PASSWORD`, and `UPDATE_CREDENTIAL`. Permit bounded trusted details `code_id`, `username`, and `email` supplied from persisted models and the authentication session.

- [ ] **Step 9: Run focused service and event tests**

```bash
pytest -q tests/test_reset_action_tokens.py tests/test_security_events.py tests/test_cli.py
```

Expected: all pass.

- [ ] **Step 10: Commit Task 3**

```bash
git add mini_keycloak/reset_credentials/authenticators.py mini_keycloak/services/action_tokens.py mini_keycloak/models/authentication.py mini_keycloak/repositories/authentication.py mini_keycloak/services/events.py mini_keycloak/store.py tests/test_reset_action_tokens.py tests/test_security_events.py tests/test_cli.py
git commit -m "feat: add reset action token lifecycle"
```

---

### Task 4: Route Browser Reset Requests Through the Processor

**Files:**
- Create: `tests/test_reset_credentials_browser_flow.py`
- Modify: `mini_keycloak/app.py`
- Modify: `mini_keycloak/authentication/browser.py`
- Modify: `mini_keycloak/services/authorization.py`
- Modify: `mini_keycloak/reset_credentials/flow.py`
- Modify: existing reset, authorization-code, persistence, concurrency, and browser tests

**Interfaces:**
- Consumes: configured flows, processor, authenticators, and token service.
- Produces: `GET /realms/<realm>/login-actions/action-token?key=...`.
- Produces: real browser completion through existing session and authorization services.

- [ ] **Step 1: Write failing initiation and selector integration tests**

Start with an authorization request and assert reset entry renders an opaque configured execution. Post `tryAnotherWay`, submit a known identifier, assert one outbox message and delivery event, then re-enter reset entry and assert the returned reset form targets the session's current execution.

- [ ] **Step 2: Write failing action-token continuation tests**

Read the delivered token from the outbox, open the action-token endpoint, and assert it reaches the password form for the same session. Malformed, expired, reused, and cross-realm tokens must return the same generic error without exposing token contents.

- [ ] **Step 3: Write failing completion tests**

Submit a valid new password and assert a redirect with the original state, a real `UserSession`, a persisted `AuthorizationCode`, successful code exchange, the browser session cookie, and consistent user ownership.

- [ ] **Step 4: Run browser-flow tests and verify route failures**

```bash
pytest -q tests/test_reset_credentials_browser_flow.py
```

Expected: failures because routes still use the reset-specific state machine and no action-token endpoint exists.

- [ ] **Step 5: Initialize browser sessions with configured flows**

Resolve the realm flow during authorization, set `flow_id`, initialize execution status, and preserve every OIDC request field.

- [ ] **Step 6: Replace reset route branching with processor dispatch**

Build the three-provider registry per request. GET calls `process_flow`; POST calls `process_action`. Render account, selection, login, password, failure, and completed outcomes without embedding transition policy in the route.

- [ ] **Step 7: Add action-token continuation**

Validate and consume `key`, set the token-user note, bind the selected user, clear selector state for continuation, and resume the processor under generic browser error handling.

- [ ] **Step 8: Complete through existing protocol services**

For `complete=True`, create a user session, issue a code, record `LOGIN`, commit once, and use the existing completion response. Replace the authorization service's semantic-execution check with a processor-completion note and one-time transition.

- [ ] **Step 9: Retain a compatibility facade**

Make `mini_keycloak/reset_credentials/flow.py` re-export provider identifiers and supported public types needed by existing callers. Remove route dependence on its old state-machine methods.

- [ ] **Step 10: Run browser, authorization, and concurrency tests**

```bash
pytest -q tests/test_reset_credentials_browser_flow.py tests/test_authorization_code.py tests/test_app_persistence.py tests/test_authentication_session_concurrency.py tests/test_browser_authentication.py
```

Expected: all pass.

- [ ] **Step 11: Commit Task 4**

```bash
git add mini_keycloak/app.py mini_keycloak/authentication/browser.py mini_keycloak/services/authorization.py mini_keycloak/reset_credentials/flow.py tests/test_reset_credentials_browser_flow.py tests/test_authorization_code.py tests/test_app_persistence.py tests/test_authentication_session_concurrency.py tests/test_browser_authentication.py
git commit -m "feat: integrate browser reset authentication flow"
```

---

### Task 5: Complete Compatibility, Migration, and Acceptance Coverage

**Files:**
- Modify: remaining reset-related tests
- Modify: `tests/test_migrations.py`
- Modify: `tests/postgres/test_postgres_migrations.py`
- Modify: `tests/postgres/test_postgres_concurrency.py`
- Modify: `README.md` only if endpoint inventory requires a neutral update

**Interfaces:**
- Consumes: all previous tasks.
- Produces: a clean upgrade path and stable public browser contract.

- [ ] **Step 1: Write failing public-contract assertions**

Require the reset and required-action path fragments, query keys `client_id`, `tab_id`, and `execution`, form fields `tryAnotherWay`, `username`, `password-new`, and `password-confirm`, and the existing forgot-password realm control.

- [ ] **Step 2: Run all reset-related tests and identify remaining semantic assumptions**

```bash
pytest -q $(rg -l "reset-credentials|ResetFlow|CHOOSE_USER_EXECUTION|EMAIL_GATE_EXECUTION" tests)
```

Expected: failures identify remaining hard-coded execution assumptions.

- [ ] **Step 3: Adapt remaining callers to configured executions**

Use provider-to-execution lookup through `AuthenticationFlowService`. Preserve paths, form names, status codes, and generic messages.

- [ ] **Step 4: Add PostgreSQL migration and consumption coverage**

Require revision `0007`, metadata parity, seeded flows, retained rows, downgrade restoration, and one-winner concurrent token consumption when the PostgreSQL test URL is configured.

- [ ] **Step 5: Run non-deployment tests**

```bash
pytest -q --ignore=tests/deployment
```

Expected: all configured tests pass; PostgreSQL tests skip only when their documented URL is absent.

- [ ] **Step 6: Run deployment contract tests**

```bash
pytest -q tests/deployment
```

Expected: all configured tests pass or report their documented environment skip.

- [ ] **Step 7: Run complete verification**

```bash
pytest -q
git diff --check
git status --short
```

Expected: zero failures, no whitespace errors, and only intended files modified.

- [ ] **Step 8: Commit Task 5**

```bash
git add mini_keycloak tests migrations README.md
git commit -m "test: complete authentication flow acceptance coverage"
```
