from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.orm.exc import StaleDataError

from mini_keycloak.authentication.constants import (
    AUTHENTICATION_FLOW_COMPLETED, AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED,
    CURRENT_AUTHENTICATION_EXECUTION,
)
from mini_keycloak.extensions import db
from mini_keycloak.models import (
    AuthenticationExecution, AuthenticationSession, AuthorizationCode, Realm,
    ResetEmail, SecurityEvent, User, UserSession,
)
from mini_keycloak.models.identity import utc_now
from mini_keycloak.oidc.errors import AccessDenied
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.reset_credentials.authenticators import ACTION_TOKEN_USER_ID
from mini_keycloak.services.authorization import AuthorizationService
from tests.helpers import form_action, query_value
from tests.test_authorization_code import AUTH, PARAMS, VERIFIER


RESET = '/realms/demo/login-actions/reset-credentials'
CONTINUE = '/realms/demo/login-actions/action-token'


def begin_reset(client, *, parameters=None):
    authorization = client.get(AUTH, query_string=PARAMS if parameters is None else parameters)
    tab_id = query_value(form_action(authorization.text, 'login-actions/authenticate'), 'tab_id')
    entry = client.get(RESET, query_string=dict(client_id='demo-app', tab_id=tab_id))
    assert entry.status_code == 200
    return tab_id, form_action(entry.text, 'login-actions/reset-credentials')


def send_reset(app, client, *, selector=False, parameters=None):
    tab_id, action = begin_reset(client, parameters=parameters)
    if selector:
        assert client.post(action, data={'tryAnotherWay': ''}).status_code == 200
    response = client.post(action, data={'username': 'demo-user'})
    assert response.status_code == 200
    with app.app_context():
        message = db.session.scalar(select(ResetEmail).where(
            ResetEmail.authentication_session_id == tab_id))
        assert message is not None
        return tab_id, message.action_token


def password_action(app, client, *, parameters=None):
    tab_id, raw = send_reset(app, client, selector=True, parameters=parameters)
    response = client.get(CONTINUE, query_string={'key': raw})
    assert response.status_code == 200
    return tab_id, form_action(response.text, 'login-actions/required-action')


def test_reset_entry_uses_configured_execution_and_preserves_oidc_request(app, client):
    tab_id, action = begin_reset(client)
    with app.app_context():
        auth = db.session.get(AuthenticationSession, tab_id)
        execution = db.session.get(AuthenticationExecution, query_value(action, 'execution'))
        assert execution is not None
        assert execution.authenticator == 'reset-credentials-choose-user'
        assert execution.flow_id == auth.flow_id == auth.realm.reset_credentials_flow_id
        assert auth.auth_notes[CURRENT_AUTHENTICATION_EXECUTION] == execution.id
        assert auth.execution_status == {execution.id: 'CHALLENGE'}
        for field in ('redirect_uri', 'response_type', 'scope', 'state', 'nonce',
                      'code_challenge', 'code_challenge_method'):
            assert getattr(auth, field) == PARAMS[field]


def test_selector_reentry_tracks_current_execution_and_one_delivery(app, client):
    tab_id, raw = send_reset(app, client, selector=True)
    for _ in range(2):
        response = client.get(RESET, query_string=dict(client_id='demo-app', tab_id=tab_id))
        action = form_action(response.text, 'login-actions/reset-credentials')
        with app.app_context():
            auth = db.session.get(AuthenticationSession, tab_id)
            assert query_value(action, 'execution') == auth.auth_notes[CURRENT_AUTHENTICATION_EXECUTION]
            assert db.session.get(AuthenticationExecution, auth.current_execution).authenticator == 'reset-credential-email'
            assert db.session.scalar(select(func.count()).select_from(ResetEmail)) == 1
            event = db.session.scalar(select(SecurityEvent).where(SecurityEvent.event_type == 'SEND_RESET_PASSWORD'))
            assert event.user_id == auth.selected_user_id
            assert event.details['code_id'] == tab_id
        assert raw not in response.text


def test_action_token_continues_same_session_and_clears_selector(app, client):
    tab_id, raw = send_reset(app, client, selector=True)
    response = client.get(CONTINUE, query_string={'key': raw})
    assert response.status_code == 200
    action = form_action(response.text, 'login-actions/required-action')
    assert query_value(action, 'tab_id') == tab_id
    assert raw not in response.text
    assert raw not in str(response.headers)
    with app.app_context():
        auth = db.session.get(AuthenticationSession, tab_id)
        assert AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED not in auth.auth_notes
        assert auth.auth_notes[ACTION_TOKEN_USER_ID] == auth.selected_user_id
        assert db.session.get(AuthenticationExecution, query_value(action, 'execution')).authenticator == 'reset-password'
        message = db.session.scalar(select(ResetEmail))
        assert message.consumed and message.consumed_at is not None
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 0


@pytest.mark.parametrize('condition', ['malformed', 'expired', 'reused', 'cross_realm', 'missing', 'duplicate'])
def test_action_token_errors_are_generic(app, client, condition, caplog):
    _, raw = send_reset(app, client)
    endpoint, query = CONTINUE, {'key': raw}
    if condition == 'malformed':
        query = {'key': raw + '.'}
    elif condition == 'expired':
        with app.app_context():
            db.session.scalar(select(ResetEmail)).expires_at = utc_now() - timedelta(seconds=1)
            db.session.commit()
    elif condition == 'reused':
        assert client.get(endpoint, query_string=query).status_code == 200
    elif condition == 'cross_realm':
        with app.app_context():
            IdentityRepository(db.session).create_realm('other')
            db.session.commit()
        endpoint = '/realms/other/login-actions/action-token'
    elif condition == 'missing':
        query = {}
    elif condition == 'duplicate':
        query = [('key', raw), ('key', raw)]
    response = client.get(endpoint, query_string=query)
    baseline = client.get(CONTINUE)
    assert response.status_code == baseline.status_code == 400
    assert response.data == baseline.data
    assert raw not in response.text + str(response.headers) + caplog.text
    with app.app_context():
        assert db.session.scalar(select(ResetEmail)).consumed == (condition == 'reused')


def test_password_completion_issues_real_session_code_and_login_event(app, client):
    tab_id, action = password_action(app, client)
    response = client.post(action, data={'password-new': 'NewPassw0rd!', 'password-confirm': 'NewPassw0rd!'})
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.location).query)
    assert query['state'] == [PARAMS['state']]
    assert 'mini_keycloak_session=' in response.headers['Set-Cookie']
    with app.app_context():
        auth = db.session.get(AuthenticationSession, tab_id)
        code = db.session.scalar(select(AuthorizationCode))
        session = db.session.scalar(select(UserSession))
        event = db.session.scalar(select(SecurityEvent).where(SecurityEvent.event_type == 'LOGIN'))
        assert code.user_id == session.user_id == event.user_id == auth.selected_user_id
        assert code.user_session_id == event.user_session_id == session.id
        assert auth.current_execution == 'authenticated'
        assert AUTHENTICATION_FLOW_COMPLETED not in auth.auth_notes
        assert ACTION_TOKEN_USER_ID not in auth.auth_notes
        assert IdentityRepository(db.session).password_matches(db.session.get(User, session.user_id), 'NewPassw0rd!')
        assert set(db.session.scalars(select(SecurityEvent.event_type))) == {
            'SEND_RESET_PASSWORD', 'UPDATE_PASSWORD', 'UPDATE_CREDENTIAL', 'LOGIN'}
    exchange = client.post('/realms/demo/protocol/openid-connect/token', data={
        'grant_type': 'authorization_code', 'client_id': 'demo-app',
        'code': query['code'][0], 'redirect_uri': PARAMS['redirect_uri'], 'code_verifier': VERIFIER})
    assert exchange.status_code == 200
    assert exchange.json['access_token']
    assert client.post(action, data={'password-new': 'AgainPassw0rd!', 'password-confirm': 'AgainPassw0rd!'}).status_code == 400
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(AuthorizationCode)) == 1
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 1


@pytest.mark.parametrize('condition', ['mismatch', 'policy'])
def test_password_challenge_preserves_continuation_for_correction(app, client, condition):
    _, action = password_action(app, client)
    with app.app_context():
        db.session.scalar(select(Realm)).password_policy = {'clauses': {'length': 12}}
        db.session.commit()
    response = client.post(action, data={'password-new': 'short',
                                       'password-confirm': 'other' if condition == 'mismatch' else 'short'})
    assert response.status_code == 200
    assert form_action(response.text, 'login-actions/required-action') == action
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(AuthorizationCode)) == 0
        assert db.session.scalar(select(AuthenticationSession)).auth_notes.get(ACTION_TOKEN_USER_ID)


@pytest.mark.parametrize('failure', [StaleDataError, AccessDenied, RuntimeError])
def test_completion_failure_rolls_back_password_session_code_and_events(app, client, monkeypatch, failure):
    _, action = password_action(app, client)
    original = AuthorizationService.issue

    def fail_after_issuance(self, result):
        original(self, result)
        raise failure()

    monkeypatch.setattr(AuthorizationService, 'issue', fail_after_issuance)
    response = client.post(action, data={'password-new': 'NewPassw0rd!', 'password-confirm': 'NewPassw0rd!'})
    assert response.status_code == (500 if failure is RuntimeError else 400)
    with app.app_context():
        assert IdentityRepository(db.session).password_matches(db.session.scalar(select(User)), 'DemoPassw0rd!')
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 0
        assert db.session.scalar(select(func.count()).select_from(AuthorizationCode)) == 0
        assert not set(db.session.scalars(select(SecurityEvent.event_type))) & {'UPDATE_PASSWORD', 'UPDATE_CREDENTIAL', 'LOGIN'}
        assert db.session.scalar(select(AuthenticationSession)).auth_notes.get(ACTION_TOKEN_USER_ID)


def test_continuation_failure_rolls_back_message_consumption(app, client):
    tab_id, raw = send_reset(app, client)
    with app.app_context():
        execution = db.session.scalar(select(AuthenticationExecution).where(
            AuthenticationExecution.authenticator == 'reset-password'))
        execution.authenticator = 'unavailable-provider'
        db.session.commit()
    response = client.get(CONTINUE, query_string={'key': raw})
    assert response.status_code == 400
    with app.app_context():
        assert not db.session.scalar(select(ResetEmail)).consumed
        auth = db.session.get(AuthenticationSession, tab_id)
        assert ACTION_TOKEN_USER_ID not in auth.auth_notes
        assert db.session.get(AuthenticationExecution, auth.current_execution).authenticator == 'reset-credential-email'


def test_completion_uses_one_database_commit(app, client):
    _, action = password_action(app, client)
    commits = []
    with app.app_context():
        session = db.session()

        def committed(_session):
            commits.append(True)

        event.listen(session, 'after_commit', committed)
        try:
            response = client.post(action, data={
                'password-new': 'NewPassw0rd!', 'password-confirm': 'NewPassw0rd!'})
        finally:
            event.remove(session, 'after_commit', committed)
    assert response.status_code == 302
    assert len(commits) == 1


@pytest.mark.parametrize('change', ['redirect_uri', 'scope', 'pkce'])
def test_completion_revalidates_current_client_configuration(app, client, change):
    parameters = dict(PARAMS)
    if change == 'pkce':
        parameters.pop('code_challenge')
        parameters.pop('code_challenge_method')
    tab_id, action = password_action(app, client, parameters=parameters)
    with app.app_context():
        auth = db.session.get(AuthenticationSession, tab_id)
        original_execution = auth.current_execution
        original_status = dict(auth.execution_status)
        original_notes = dict(auth.auth_notes)
        if change == 'redirect_uri':
            auth.client.redirect_uris = ['https://configured.example.test/callback']
        elif change == 'scope':
            auth.client.default_scopes = ['openid', 'email']
            auth.client.optional_scopes = []
        else:
            assert auth.client.pkce_policy == 'optional'
            auth.client.pkce_policy = 'S256'
        db.session.commit()

    response = client.post(action, data={
        'password-new': 'NewPassw0rd!', 'password-confirm': 'NewPassw0rd!'})
    assert response.status_code == 400
    assert response.data == client.get(CONTINUE).data
    assert 'Location' not in response.headers
    assert 'Set-Cookie' not in response.headers
    with app.app_context():
        auth = db.session.get(AuthenticationSession, tab_id)
        assert auth.current_execution == original_execution
        assert auth.execution_status == original_status
        assert auth.auth_notes == original_notes
        assert AUTHENTICATION_FLOW_COMPLETED not in auth.auth_notes
        assert IdentityRepository(db.session).password_matches(auth.selected_user, 'DemoPassw0rd!')
        assert not IdentityRepository(db.session).password_matches(auth.selected_user, 'NewPassw0rd!')
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 0
        assert db.session.scalar(select(func.count()).select_from(AuthorizationCode)) == 0
        assert set(db.session.scalars(select(SecurityEvent.event_type))) == {'SEND_RESET_PASSWORD'}
        for field in ('redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method'):
            assert getattr(auth, field) == parameters.get(field)


@pytest.mark.parametrize('account', ['known', 'unknown', 'disabled', 'no_email'])
def test_account_lookup_has_uniform_browser_response(app, client, account):
    if account in {'disabled', 'no_email'}:
        with app.app_context():
            user = db.session.scalar(select(User))
            if account == 'disabled':
                user.enabled = False
            else:
                user.email = None
            db.session.commit()
    _, action = begin_reset(client)
    response = client.post(action, data={'username': 'missing' if account == 'unknown' else 'demo-user'})
    assert response.status_code == 200
    assert 'If the account exists, reset instructions have been sent.' in response.text
    assert 'login-actions/authenticate' in response.text
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(ResetEmail)) == int(account == 'known')
