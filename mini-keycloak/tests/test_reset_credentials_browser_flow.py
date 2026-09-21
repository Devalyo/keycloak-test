from datetime import timedelta
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import pytest
import jwt
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
from mini_keycloak.reset_credentials.update_password import UPDATE_PASSWORD
from mini_keycloak.services.authorization import AuthorizationService
from tests.helpers import form_action, link_href, query_value
from tests.test_authorization_code import AUTH, PARAMS, VERIFIER


RESET = '/realms/demo/login-actions/reset-credentials'
CONTINUE = '/realms/demo/login-actions/action-token'


def begin_reset(client, *, parameters=None):
    authorization = client.get(AUTH, query_string=PARAMS if parameters is None else parameters)
    reset_url = link_href(authorization.text, 'login-actions/reset-credentials')
    tab_id = query_value(reset_url, 'tab_id')
    entry = client.get(reset_url)
    assert entry.status_code == 200
    return tab_id, form_action(entry.text, 'login-actions/reset-credentials')


def send_reset(app, client, *, selector=False, parameters=None, return_response=False):
    tab_id, action = begin_reset(client, parameters=parameters)
    if selector:
        selector_response = client.post(action, data={'tryAnotherWay': ''})
        assert selector_response.status_code == 200
        action = form_action(selector_response.text, 'login-actions/reset-credentials')
    response = client.post(action, data={'username': 'demo-user'})
    assert response.status_code == 200
    with app.app_context():
        message = db.session.scalar(select(ResetEmail).where(
            ResetEmail.authentication_session_id == tab_id))
        assert message is not None
        result = (tab_id, message.action_token, response)
        return result if return_response else result[:2]


def password_action(app, client, *, parameters=None):
    tab_id, raw = send_reset(app, client, selector=True, parameters=parameters)
    response = client.get(CONTINUE, query_string={'key': raw})
    assert response.status_code == 200
    return tab_id, form_action(response.text, 'login-actions/required-action')


@pytest.mark.parametrize('allowed', [False, True])
def test_reset_public_form_contract_and_realm_control(app, client, allowed):
    with app.app_context():
        db.session.scalar(select(Realm)).forgot_password_allowed = allowed
        db.session.commit()
    authorization = client.get(AUTH, query_string=PARAMS)
    assert authorization.status_code == 200
    assert ('Forgot password?' in authorization.text) is allowed
    login_action = form_action(authorization.text, 'login-actions/authenticate')
    tab_id = query_value(login_action, 'tab_id')
    if allowed:
        reset_url = link_href(authorization.text, 'login-actions/reset-credentials')
    else:
        parts = urlsplit(login_action)
        query = parse_qs(parts.query)
        query.pop('execution')
        reset_url = urlunsplit((parts.scheme, parts.netloc,
                                parts.path.replace('/authenticate', '/reset-credentials'),
                                urlencode(query, doseq=True), parts.fragment))
    response = client.get(reset_url)
    if not allowed:
        assert response.status_code == 400
        assert response.data == client.get(RESET).data
        with app.app_context():
            assert db.session.scalar(select(func.count()).select_from(ResetEmail)) == 0
        return
    assert response.status_code == 200
    action = form_action(response.text, 'login-actions/reset-credentials')
    assert urlsplit(action).path == '/realms/demo/login-actions/reset-credentials'
    assert set(parse_qs(urlsplit(action).query)) == {
        'client_id', 'tab_id', 'execution', 'session_code'}
    assert query_value(action, 'client_id') == 'demo-app'
    assert query_value(action, 'tab_id') == tab_id
    assert 'name="username"' in response.text
    assert 'name="tryAnotherWay"' in response.text
    selector = client.post(action, data={'tryAnotherWay': ''})
    assert selector.status_code == 200
    selector_action = form_action(selector.text, 'login-actions/reset-credentials')
    assert query_value(selector_action, 'session_code') != query_value(action, 'session_code')
    for name in ('client_id', 'tab_id', 'execution'):
        assert query_value(selector_action, name) == query_value(action, name)
    assert 'name="username"' in selector.text


@pytest.mark.parametrize('condition', ['missing_session_code', 'malformed_session_code',
                                        'stale_session_code', 'wrong_browser_binding',
                                        'non_ascii_browser_binding', 'wrong_client',
                                        'wrong_tab', 'noncurrent_execution'])
def test_session_code_and_browser_binding_reject_invalid_reset_submission(
        app, client, condition):
    _, action = begin_reset(client)
    candidate = action
    submitting_client = client
    if condition == 'missing_session_code':
        parts = urlsplit(action)
        query = parse_qs(parts.query)
        query.pop('session_code')
        candidate = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                urlencode(query, doseq=True), parts.fragment))
    elif condition == 'malformed_session_code':
        candidate = action.replace(query_value(action, 'session_code'), 'invalid')
    elif condition == 'stale_session_code':
        refreshed = client.post(action, data={'tryAnotherWay': ''})
        assert refreshed.status_code == 200
    elif condition == 'wrong_browser_binding':
        submitting_client = app.test_client()
    elif condition == 'non_ascii_browser_binding':
        tab_id = query_value(action, 'tab_id')
        client.set_cookie('mini_keycloak_login_' + tab_id, 'é',
                          path='/realms/demo/login-actions/')
    else:
        parts = urlsplit(action)
        query = parse_qs(parts.query)
        query[{'wrong_client': 'client_id', 'wrong_tab': 'tab_id',
               'noncurrent_execution': 'execution'}[condition]] = ['different']
        candidate = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                urlencode(query, doseq=True), parts.fragment))

    with app.app_context():
        auth = db.session.get(AuthenticationSession, query_value(action, 'tab_id'))
        before = (auth.version, auth.session_code_hash, auth.browser_binding_generation,
                  list(auth.required_actions), auth.current_required_action,
                  dict(auth.execution_status), dict(auth.auth_notes))
    response = submitting_client.post(candidate, data={'username': 'demo-user'})
    assert response.status_code == 400
    assert response.data == client.get(CONTINUE).data
    with app.app_context():
        auth = db.session.get(AuthenticationSession, query_value(action, 'tab_id'))
        assert (auth.version, auth.session_code_hash, auth.browser_binding_generation,
                list(auth.required_actions), auth.current_required_action,
                dict(auth.execution_status), dict(auth.auth_notes)) == before


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


def test_ordinary_login_after_reset_selection_clears_execution_notes(app, client):
    authorization = client.get(AUTH, query_string=PARAMS)
    login_action = form_action(authorization.text, 'login-actions/authenticate')
    tab_id = query_value(login_action, 'tab_id')
    reset = client.get(link_href(authorization.text, 'login-actions/reset-credentials'))
    action = form_action(reset.text, 'login-actions/reset-credentials')
    selector = client.post(action, data={'tryAnotherWay': ''})
    assert selector.status_code == 200
    current = form_action(selector.text, 'login-actions/reset-credentials')
    with app.app_context():
        auth = db.session.get(AuthenticationSession, tab_id)
        assert auth.auth_notes[CURRENT_AUTHENTICATION_EXECUTION] == query_value(action, 'execution')
        assert auth.auth_notes[AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED] == 'true'
        auth.auth_notes['operator'] = 'retained'
        db.session.commit()
    parts = urlsplit(current)
    query = parse_qs(parts.query)
    query['execution'] = ['login']
    current_login_action = urlunsplit((parts.scheme, parts.netloc,
        parts.path.replace('/reset-credentials', '/authenticate'),
        urlencode(query, doseq=True), parts.fragment))
    response = client.post(current_login_action,
        data={'username': 'demo-user', 'password': 'DemoPassw0rd!'})
    assert response.status_code == 302
    assert query_value(response.location, 'state') == PARAMS['state']
    with app.app_context():
        auth = db.session.get(AuthenticationSession, tab_id)
        assert auth.current_execution == 'authenticated'
        assert auth.auth_notes == {'operator': 'retained'}
        assert db.session.scalar(select(func.count()).select_from(AuthorizationCode)) == 1
    assert client.post(login_action, data={'username': 'demo-user', 'password': 'DemoPassw0rd!'}).status_code == 400


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
        assert query_value(action, 'execution') == UPDATE_PASSWORD
        assert auth.current_required_action == UPDATE_PASSWORD
        message = db.session.scalar(select(ResetEmail))
        assert message.consumed and message.consumed_at is not None
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 0


@pytest.mark.parametrize('condition', ['malformed', 'expired', 'reused', 'cross_realm',
                                        'missing', 'duplicate', 'unknown_type'])
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
    elif condition == 'unknown_type':
        with app.app_context():
            message = db.session.scalar(select(ResetEmail))
            claims = jwt.decode(raw, app.config['SECRET_KEY'], algorithms=['HS256'])
            claims['typ'] = 'unknown-action'
            raw = jwt.encode(claims, app.config['SECRET_KEY'], algorithm='HS256')
            message.action_token_hash = __import__('hashlib').sha256(raw.encode()).hexdigest()
            db.session.commit()
        query = {'key': raw}
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
        assert CURRENT_AUTHENTICATION_EXECUTION not in auth.auth_notes
        assert AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED not in auth.auth_notes
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


def test_legitimate_same_browser_reset_completion(app, client):
    _, action = password_action(app, client)
    assert query_value(action, 'session_code')
    response = client.post(action, data={
        'password-new': 'ChangedPassw0rd!',
        'password-confirm': 'ChangedPassw0rd!',
    })
    assert response.status_code == 302
    code = query_value(response.location, 'code')
    exchange = client.post('/realms/demo/protocol/openid-connect/token', data={
        'grant_type': 'authorization_code',
        'client_id': 'demo-app',
        'code': code,
        'redirect_uri': PARAMS['redirect_uri'],
        'code_verifier': VERIFIER,
    })
    assert exchange.status_code == 200
    with app.app_context():
        user = db.session.scalar(select(User))
        assert IdentityRepository(db.session).password_matches(user, 'ChangedPassw0rd!')


def test_legitimate_different_browser_reset_completion(app, client):
    tab_id, action = begin_reset(client)
    sent = client.post(action, data={'username': 'demo-user'})
    assert sent.status_code == 200
    prior_url = link_href(sent.text, 'login-actions/reset-credentials')
    cookie_name = 'mini_keycloak_login_' + tab_id
    cookie_path = '/realms/demo/login-actions/'
    initiator_binding = client.get_cookie(cookie_name, path=cookie_path)
    assert initiator_binding is not None
    with app.app_context():
        raw = db.session.scalar(select(ResetEmail)).action_token
        generation_before = db.session.get(
            AuthenticationSession, tab_id
        ).browser_binding_generation

    consumer = app.test_client()
    continued = consumer.get(CONTINUE, query_string={'key': raw})
    assert continued.status_code == 200
    password_url = form_action(continued.text, 'login-actions/required-action')
    consumer_binding = consumer.get_cookie(cookie_name, path=cookie_path)
    assert consumer_binding is not None
    assert consumer_binding.value != initiator_binding.value
    assert client.get(prior_url).status_code == 400
    with app.app_context():
        assert db.session.get(
            AuthenticationSession, tab_id
        ).browser_binding_generation == generation_before + 1

    completed = consumer.post(password_url, data={
        'password-new': 'ChangedPassw0rd!',
        'password-confirm': 'ChangedPassw0rd!',
    })
    assert completed.status_code == 302
    assert query_value(completed.location, 'code')


@pytest.mark.parametrize('condition', ['mismatch', 'policy'])
def test_password_challenge_preserves_continuation_for_correction(app, client, condition):
    _, action = password_action(app, client)
    with app.app_context():
        db.session.scalar(select(Realm)).password_policy = {'clauses': {'length': 12}}
        db.session.commit()
    response = client.post(action, data={'password-new': 'short',
                                       'password-confirm': 'other' if condition == 'mismatch' else 'short'})
    assert response.status_code == 200
    retry = form_action(response.text, 'login-actions/required-action')
    assert query_value(retry, 'session_code') != query_value(action, 'session_code')
    for name in ('client_id', 'tab_id', 'execution'):
        assert query_value(retry, name) == query_value(action, name)
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(AuthorizationCode)) == 0
        assert db.session.scalar(select(AuthenticationSession)).auth_notes.get(ACTION_TOKEN_USER_ID)


def test_failure_after_credential_mutation_rolls_back_entire_completion(
        app, client, monkeypatch):
    tab_id, action = password_action(app, client)
    with app.app_context():
        auth = db.session.get(AuthenticationSession, tab_id)
        continuation_before = (
            auth.session_code_hash, auth.browser_binding_generation,
            list(auth.required_actions), auth.current_required_action,
            auth.version, dict(auth.auth_notes), dict(auth.execution_status),
        )
        events_before = list(db.session.scalars(select(SecurityEvent.event_type)))
    original = IdentityRepository.set_password

    def mutate_then_fail(self, user, password):
        original(self, user, password)
        raise RuntimeError("injected failure")

    monkeypatch.setattr(IdentityRepository, 'set_password', mutate_then_fail)

    response = client.post(action, data={
        'password-new': 'NewPassw0rd!',
        'password-confirm': 'NewPassw0rd!',
    })

    assert response.status_code == 500
    with app.app_context():
        assert IdentityRepository(db.session).password_matches(
            db.session.scalar(select(User)), 'DemoPassw0rd!')
        assert list(db.session.scalars(select(SecurityEvent.event_type))) == events_before
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 0
        assert db.session.scalar(select(func.count()).select_from(AuthorizationCode)) == 0
        auth = db.session.get(AuthenticationSession, tab_id)
        assert (
            auth.session_code_hash, auth.browser_binding_generation,
            list(auth.required_actions), auth.current_required_action,
            auth.version, dict(auth.auth_notes), dict(auth.execution_status),
        ) == continuation_before


@pytest.mark.parametrize('failure', [StaleDataError, AccessDenied, RuntimeError])
def test_completion_failure_rolls_back_password_session_code_and_events(app, client, monkeypatch, failure):
    tab_id, action = password_action(app, client)
    with app.app_context():
        auth = db.session.get(AuthenticationSession, tab_id)
        continuation_before = (
            auth.session_code_hash, auth.browser_binding_generation,
            list(auth.required_actions), auth.current_required_action,
            auth.version, dict(auth.auth_notes), dict(auth.execution_status),
        )
        events_before = list(db.session.scalars(select(SecurityEvent.event_type)))
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
        assert list(db.session.scalars(select(SecurityEvent.event_type))) == events_before
        auth = db.session.get(AuthenticationSession, tab_id)
        assert auth.auth_notes.get(ACTION_TOKEN_USER_ID)
        assert (
            auth.session_code_hash, auth.browser_binding_generation,
            list(auth.required_actions), auth.current_required_action,
            auth.version, dict(auth.auth_notes), dict(auth.execution_status),
        ) == continuation_before


def test_continuation_failure_rolls_back_message_consumption(app, client):
    tab_id, raw = send_reset(app, client)
    with app.app_context():
        execution = db.session.scalar(select(AuthenticationExecution).where(
            AuthenticationExecution.authenticator == 'reset-password'))
        execution.authenticator = 'unavailable-provider'
        db.session.commit()
        auth = db.session.get(AuthenticationSession, tab_id)
        continuation_before = (
            auth.session_code_hash, auth.browser_binding_generation,
            list(auth.required_actions), auth.current_required_action,
            auth.version, dict(auth.auth_notes), dict(auth.execution_status),
        )
    response = client.get(CONTINUE, query_string={'key': raw})
    assert response.status_code == 400
    with app.app_context():
        assert not db.session.scalar(select(ResetEmail)).consumed
        auth = db.session.get(AuthenticationSession, tab_id)
        assert ACTION_TOKEN_USER_ID not in auth.auth_notes
        assert db.session.get(AuthenticationExecution, auth.current_execution).authenticator == 'reset-credential-email'
        assert (
            auth.session_code_hash, auth.browser_binding_generation,
            list(auth.required_actions), auth.current_required_action,
            auth.version, dict(auth.auth_notes), dict(auth.execution_status),
        ) == continuation_before


def test_failure_after_token_flow_resume_rolls_back_entire_continuation(
    app, client, monkeypatch
):
    tab_id, raw = send_reset(app, client)
    with app.app_context():
        auth = db.session.get(AuthenticationSession, tab_id)
        continuation_before = (
            auth.session_code_hash, auth.browser_binding_generation,
            auth.selected_user_id, list(auth.required_actions),
            auth.current_required_action, auth.version, dict(auth.auth_notes),
            dict(auth.execution_status), auth.current_execution,
        )

    def fail_browser_binding(_authentication_session):
        raise RuntimeError("injected failure")

    monkeypatch.setattr(
        "mini_keycloak.reset_credentials.action_token.browser_binding",
        fail_browser_binding,
    )
    response = client.get(CONTINUE, query_string={"key": raw})
    assert response.status_code == 500
    with app.app_context():
        assert not db.session.scalar(select(ResetEmail)).consumed
        auth = db.session.get(AuthenticationSession, tab_id)
        assert (
            auth.session_code_hash, auth.browser_binding_generation,
            auth.selected_user_id, list(auth.required_actions),
            auth.current_required_action, auth.version, dict(auth.auth_notes),
            dict(auth.execution_status), auth.current_execution,
        ) == continuation_before


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
