import pytest
from flask import request
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm.exc import StaleDataError

from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationSession, ResetEmail
from mini_keycloak.authentication import AuthenticationProcessor, AuthenticatorRegistry
from mini_keycloak.authentication.constants import (
    AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED, RESET_CREDENTIALS_CHOOSE_USER,
    RESET_CREDENTIAL_EMAIL, RESET_PASSWORD,
)
from mini_keycloak.reset_credentials.authenticators import (
    ACTION_TOKEN_USER_ID, ResetCredentialChooseUser, ResetCredentialEmail, ResetPassword,
)
from mini_keycloak.services.action_tokens import ResetActionTokenService
from mini_keycloak.services.authentication_flows import AuthenticationFlowService
from mini_keycloak.services.bootstrap import ensure_demo_realm
from mini_keycloak.store import PersistentStore


def _processor(session, tab_id):
    return AuthenticationProcessor(session, realm_name='demo', client_id='demo-app',
        tab_id=tab_id, registry=AuthenticatorRegistry({
            RESET_CREDENTIALS_CHOOSE_USER: ResetCredentialChooseUser(),
            RESET_CREDENTIAL_EMAIL: ResetCredentialEmail(),
            RESET_PASSWORD: ResetPassword(),
        }))


def _create_authentication_session(*, advance_to_password: bool = False):
    realm = ensure_demo_realm(db.session)
    db.session.commit()
    store = PersistentStore(db.session)
    client = store.get_client(realm.id, "demo-app")
    assert client is not None
    executions = AuthenticationFlowService(db.session).executions(realm.reset_credentials_flow_id)
    auth_session = store.create_auth_session(realm, client, client.redirect_uris[0], executions[0].id)
    auth_session.flow_id = realm.reset_credentials_flow_id
    if advance_to_password:
        processor = _processor(db.session, auth_session.tab_id)
        processor.process_action(executions[0].id, {'username': 'demo-user'})
        message = db.session.scalar(select(ResetEmail))
        _, user = ResetActionTokenService(db.session).consume('demo', message.action_token)
        auth_session.auth_notes[ACTION_TOKEN_USER_ID] = user.id
        assert processor.process_flow().page == 'password'
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
            version, execution = winner.version, winner.current_execution
            assert winner.version == loser.version

            winner.auth_notes["winner"] = "true"
            winner_session.commit()

            loser.auth_notes['loser'] = 'true'
            with pytest.raises(StaleDataError):
                loser_session.commit()
            loser_session.rollback()

        persisted = db.session.get(AuthenticationSession, tab_id)
        assert persisted is not None
        assert persisted.version == version + 1
        assert persisted.current_execution == execution
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
            winner_flow = _processor(winner_session, tab_id)
            loser_flow = _processor(loser_session, tab_id)

            winner_flow.process_action(winner_auth.current_execution,
                {'password-new': 'WinnerPassw0rd!', 'password-confirm': 'WinnerPassw0rd!'})
            winner_session.commit()

            with pytest.raises(StaleDataError):
                loser_flow.process_action(loser_auth.current_execution,
                    {'password-new': 'LoserPassw0rd!', 'password-confirm': 'LoserPassw0rd!'})
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
        execution = db.session.get(AuthenticationSession, tab_id).current_execution
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
            "execution": execution,
        },
        data={"tryAnotherWay": ""},
    )

    assert response.status_code == 400
    with db_app.app_context():
        persisted = db.session.get(AuthenticationSession, tab_id)
        assert persisted is not None
        assert persisted.current_execution == execution
        assert persisted.auth_notes == {"competing": "true"}
        assert AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED not in persisted.auth_notes
