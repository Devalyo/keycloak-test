import re
import secrets

import pytest
from sqlalchemy import select

from mini_keycloak.authentication.session_codes import (
    SessionCodeChecks,
    SessionContinuation,
    binding_matches,
    browser_binding,
)
from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationSession, Client, Realm
from mini_keycloak.models.identity import utc_now
from mini_keycloak.services.authentication_flows import AuthenticationFlowService
from mini_keycloak.store import PersistentStore


def create_authentication_session():
    realm = db.session.scalar(select(Realm))
    client = db.session.scalar(select(Client).where(Client.realm_id == realm.id))
    flow = AuthenticationFlowService(db.session).ensure_reset_flow(realm)
    execution = AuthenticationFlowService(db.session).executions(flow.id)[0]
    auth = AuthenticationSession(
        tab_id=secrets.token_urlsafe(18),
        realm_id=realm.id,
        client_id=client.id,
        redirect_uri=client.redirect_uris[0],
        current_execution=execution.id,
        flow_id=flow.id,
        execution_status={execution.id: "CHALLENGE"},
        auth_notes={"operator": "retained"},
        expires_at=utc_now().replace(year=utc_now().year + 1),
    )
    db.session.add(auth)
    db.session.flush()
    return auth


def test_issue_stores_only_digest_and_verify_has_no_side_effects(app):
    with app.app_context():
        auth = create_authentication_session()
        original = (
            auth.current_execution,
            dict(auth.execution_status),
            dict(auth.auth_notes),
        )

        raw_code = SessionContinuation.issue(auth)

        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", raw_code)
        assert re.fullmatch(r"[0-9a-f]{64}", auth.session_code_hash)
        assert raw_code != auth.session_code_hash
        assert SessionContinuation.verify(auth, raw_code)
        assert not SessionContinuation.verify(auth, "malformed")
        assert (
            auth.current_execution,
            dict(auth.execution_status),
            dict(auth.auth_notes),
        ) == original


def test_rotate_replaces_the_only_accepted_code(app):
    with app.app_context():
        auth = create_authentication_session()
        first = SessionContinuation.issue(auth)

        second = SessionContinuation.rotate(auth, first)

        assert second != first
        assert not SessionContinuation.verify(auth, first)
        assert SessionContinuation.verify(auth, second)


def test_replayed_code_does_not_change_active_continuation(app):
    with app.app_context():
        auth = create_authentication_session()
        first = SessionContinuation.issue(auth)
        second = SessionContinuation.rotate(auth, first)
        active_digest = auth.session_code_hash

        with pytest.raises(ValueError, match="Invalid authentication request"):
            SessionContinuation.rotate(auth, first)

        assert auth.session_code_hash == active_digest
        assert SessionContinuation.verify(auth, second)


def test_browser_binding_is_scoped_to_session_and_generation(app):
    with app.app_context():
        first = create_authentication_session()
        second = create_authentication_session()
        token = browser_binding(first)

        assert token == browser_binding(first)
        assert binding_matches(first, token)
        assert not binding_matches(second, token)
        assert not binding_matches(first, "malformed")

        first.browser_binding_generation += 1

        assert not binding_matches(first, token)
        assert binding_matches(first, browser_binding(first))


def test_browser_binding_rejects_non_ascii_input(app):
    with app.app_context():
        auth = create_authentication_session()
        assert not binding_matches(auth, "é" * 64)


def continuation_snapshot(auth):
    return (
        auth.version,
        auth.session_code_hash,
        auth.browser_binding_generation,
        list(auth.required_actions),
        auth.current_required_action,
        dict(auth.execution_status),
        dict(auth.auth_notes),
    )


@pytest.mark.parametrize(
    "condition",
    [
        "missing",
        "malformed",
        "stale",
        "non_ascii",
        "wrong_browser",
        "wrong_client",
        "wrong_tab",
        "noncurrent_execution",
    ],
)
def test_session_code_checks_reject_without_mutating_state(app, condition):
    with app.app_context():
        auth = create_authentication_session()
        auth.auth_notes["current.authentication.execution"] = auth.current_execution
        raw_code = SessionContinuation.issue(auth)
        binding = browser_binding(auth)
        candidate = raw_code
        query = {
            "client_id": auth.client.client_id,
            "tab_id": auth.tab_id,
            "execution": auth.current_execution,
            "session_code": raw_code,
        }
        if condition == "missing":
            query.pop("session_code")
        elif condition == "malformed":
            query["session_code"] = "malformed"
        elif condition == "stale":
            candidate = raw_code
            query["session_code"] = SessionContinuation.rotate(auth, raw_code)
            raw_code = candidate
            query["session_code"] = raw_code
        elif condition == "non_ascii":
            query["session_code"] = "é"
        elif condition == "wrong_browser":
            binding = "0" * 64
        elif condition == "wrong_client":
            query["client_id"] = "different-client"
        elif condition == "wrong_tab":
            query["tab_id"] = "different-tab"
        elif condition == "noncurrent_execution":
            query["execution"] = "different-execution"
        db.session.commit()
        before = continuation_snapshot(auth)
        cookie = f"mini_keycloak_login_{auth.tab_id}={binding}"

        with app.test_request_context(
            "/realms/demo/login-actions/reset-credentials",
            method="POST",
            query_string=query,
            headers={"Cookie": cookie},
        ):
            with pytest.raises(ValueError, match="Invalid authentication request"):
                SessionCodeChecks(PersistentStore(db.session)).validate(
                    auth.realm.name, expected_execution=auth.current_execution
                )

        assert continuation_snapshot(auth) == before


def test_session_code_checks_validate_before_explicit_rotation(app):
    with app.app_context():
        auth = create_authentication_session()
        auth.auth_notes["current.authentication.execution"] = auth.current_execution
        raw_code = SessionContinuation.issue(auth)
        binding = browser_binding(auth)
        db.session.commit()
        before = continuation_snapshot(auth)
        query = {
            "client_id": auth.client.client_id,
            "tab_id": auth.tab_id,
            "execution": auth.current_execution,
            "session_code": raw_code,
        }

        with app.test_request_context(
            "/realms/demo/login-actions/reset-credentials",
            method="POST",
            query_string=query,
            headers={"Cookie": f"mini_keycloak_login_{auth.tab_id}={binding}"},
        ):
            checks = SessionCodeChecks(PersistentStore(db.session))
            assert checks.validate(
                auth.realm.name, expected_execution=auth.current_execution
            ) is auth
            assert continuation_snapshot(auth) == before
            next_code = checks.rotate(auth)

        assert next_code != raw_code
        assert SessionContinuation.verify(auth, next_code)
