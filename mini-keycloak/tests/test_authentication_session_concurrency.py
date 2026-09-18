import pytest
from flask import request
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm.exc import StaleDataError

from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationSession
from mini_keycloak.reset_credentials.flow import (
    AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED,
    CHOOSE_USER_EXECUTION,
    EMAIL_GATE_EXECUTION,
    ResetFlow,
)
from mini_keycloak.services.bootstrap import ensure_demo_realm
from mini_keycloak.store import PersistentStore


def _create_authentication_session(*, advance_to_password: bool = False):
    realm = ensure_demo_realm(db.session)
    db.session.commit()
    store = PersistentStore(db.session)
    client = store.get_client(realm.id, "demo-app")
    assert client is not None
    flow = ResetFlow(store)
    auth_session = flow.create_session(realm, client, client.redirect_uris[0])
    if advance_to_password:
        flow.show_selector(auth_session)
        flow.submit_identifier(auth_session, "demo-user")
        flow.submit_email_gate(auth_session)
    db.session.commit()
    return auth_session.tab_id, realm.id, auth_session.selected_user_id


def test_concurrent_authentication_session_transition_rejects_stale_writer(db_app):
    with db_app.app_context():
        tab_id, _, _ = _create_authentication_session()
        db.session.remove()
        sessions = sessionmaker(bind=db.engine, expire_on_commit=False)

        with sessions() as winner_session, sessions() as loser_session:
            winner = winner_session.get(AuthenticationSession, tab_id)
            loser = loser_session.get(AuthenticationSession, tab_id)
            assert winner is not None
            assert loser is not None
            assert winner.version == loser.version == 1

            winner.auth_notes["winner"] = "true"
            winner_session.commit()

            loser.current_execution = EMAIL_GATE_EXECUTION
            with pytest.raises(StaleDataError):
                loser_session.commit()
            loser_session.rollback()

        persisted = db.session.get(AuthenticationSession, tab_id)
        assert persisted is not None
        assert persisted.version == 2
        assert persisted.current_execution == CHOOSE_USER_EXECUTION
        assert persisted.auth_notes == {"winner": "true"}


def test_concurrent_password_update_loser_cannot_overwrite_winner(db_app):
    with db_app.app_context():
        tab_id, realm_id, user_id = _create_authentication_session(
            advance_to_password=True
        )
        assert user_id is not None
        db.session.remove()
        sessions = sessionmaker(bind=db.engine, expire_on_commit=False)

        with sessions() as winner_session, sessions() as loser_session:
            winner_auth = winner_session.get(AuthenticationSession, tab_id)
            loser_auth = loser_session.get(AuthenticationSession, tab_id)
            assert winner_auth is not None
            assert loser_auth is not None
            winner_flow = ResetFlow(PersistentStore(winner_session))
            loser_flow = ResetFlow(PersistentStore(loser_session))

            winner_flow.update_password(winner_auth, "WinnerPassw0rd!")
            winner_session.commit()

            loser_flow.update_password(loser_auth, "LoserPassw0rd!")
            with pytest.raises(StaleDataError):
                loser_session.commit()
            loser_session.rollback()

        verifier = PersistentStore(db.session)
        user = verifier.get_user(realm_id, user_id)
        assert user is not None
        assert verifier.password_matches(user, "WinnerPassw0rd!")
        assert not verifier.password_matches(user, "LoserPassw0rd!")


def test_http_flow_returns_400_and_rolls_back_stale_transition(db_app):
    with db_app.app_context():
        tab_id, _, _ = _create_authentication_session()
    raced = False
    held_request_rows = []

    @db_app.before_request
    def commit_competing_transition():
        nonlocal raced
        if (
            raced
            or request.method != "POST"
            or not request.path.endswith("/login-actions/reset-credentials")
        ):
            return

        request_auth = db.session.get(AuthenticationSession, tab_id)
        assert request_auth is not None
        held_request_rows.append(request_auth)
        with Session(db.engine, expire_on_commit=False) as competing_session:
            competing_auth = competing_session.get(AuthenticationSession, tab_id)
            assert competing_auth is not None
            competing_auth.auth_notes["competing"] = "true"
            competing_session.commit()
        raced = True

    db_app.config["PROPAGATE_EXCEPTIONS"] = False
    response = db_app.test_client().post(
        "/realms/demo/login-actions/reset-credentials",
        query_string={
            "client_id": "demo-app",
            "tab_id": tab_id,
            "execution": CHOOSE_USER_EXECUTION,
        },
        data={"tryAnotherWay": ""},
    )

    assert response.status_code == 400
    with db_app.app_context():
        persisted = db.session.get(AuthenticationSession, tab_id)
        assert persisted is not None
        assert persisted.current_execution == CHOOSE_USER_EXECUTION
        assert persisted.auth_notes == {"competing": "true"}
        assert AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED not in persisted.auth_notes
