from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.cookies import SimpleCookie
from threading import Barrier

import pytest
from sqlalchemy import func, select

from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationSession, AuthorizationCode, UserSession
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.repositories.sessions import UserSessionRepository
from tests.helpers import form_action, query_value
from tests.test_browser_authentication import AUTH, PARAMS, begin, login


CREDENTIALS = {'username': 'demo-user', 'password': 'DemoPassw0rd!'}
LOGIN_PATH = '/realms/demo/login-actions/authenticate'


def preauth_cookie(response):
    cookies = SimpleCookie()
    for header in response.headers.getlist('Set-Cookie'):
        cookies.load(header)
    return next((cookie for name, cookie in cookies.items()
                 if name.startswith('mini_keycloak_login_')), None)


@pytest.mark.parametrize('secure', [False, True])
def test_authorization_issues_opaque_scoped_preauth_cookie(app, client, secure):
    app.config['SESSION_COOKIE_SECURE'] = secure
    response = begin(client)
    cookie = preauth_cookie(response)
    assert cookie is not None
    action = form_action(response.text, 'login-actions/authenticate')
    assert cookie['httponly'] and cookie['samesite'] == 'Lax'
    assert bool(cookie['secure']) is secure
    assert cookie['path'] == LOGIN_PATH and not cookie['domain']
    assert 0 < int(cookie['max-age']) <= 1800
    assert len(cookie.value) >= 32
    assert query_value(action, 'tab_id') not in cookie.value
    assert cookie.value not in response.text


@pytest.mark.parametrize('binding', ['missing', 'tampered', 'other-tab', 'other-realm'])
def test_invalid_browser_binding_rejected_before_credentials(app, client, monkeypatch, binding):
    response = begin(client)
    action = form_action(response.text, 'login-actions/authenticate')
    cookie = preauth_cookie(response)
    assert cookie is not None
    if binding == 'missing':
        client.delete_cookie(cookie.key, path=cookie['path'])
    elif binding == 'tampered':
        client.set_cookie(cookie.key, cookie.value + 'x', path=cookie['path'])
    else:
        if binding == 'other-realm':
            with app.app_context():
                identities = IdentityRepository(db.session)
                other = identities.create_realm('other')
                identities.create_client(other.id, 'demo-app', redirect_uris=[PARAMS['redirect_uri']])
                db.session.commit()
            other_response = client.get(AUTH.replace('/demo/', '/other/'), query_string=PARAMS)
        else:
            other_response = begin(client)
        other_cookie = preauth_cookie(other_response)
        assert other_cookie is not None
        client.set_cookie(cookie.key, other_cookie.value, path=cookie['path'])

    def unexpected_lookup(*args, **kwargs):
        pytest.fail('Unbound login must be rejected before credential lookup')

    monkeypatch.setattr(IdentityRepository, 'find_user', unexpected_lookup)
    rejected = client.post(action, data=CREDENTIALS, headers={'Origin': 'http://localhost'})
    generic = client.post(LOGIN_PATH, data=CREDENTIALS)
    assert rejected.status_code == generic.status_code == 400
    assert rejected.data == generic.data
    assert 'Set-Cookie' not in rejected.headers
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 0
        session = db.session.get(AuthenticationSession, query_value(action, 'tab_id'))
        assert session.current_execution == 'choose-user'
        assert session.selected_user_id is None


def test_unbound_login_cannot_replace_existing_browser_session(app, client):
    assert login(client).status_code == 302
    signed_in_cookie = client.get_cookie('mini_keycloak_session', path='/realms/demo/')
    with app.app_context():
        existing = db.session.scalar(select(UserSession))
        existing_id, existing_user_id = existing.id, existing.user_id
        IdentityRepository(db.session).create_user(existing.realm_id, 'second-user', None, 'SecondPassw0rd!')
        db.session.commit()
    independent_browser = app.test_client()
    action = form_action(begin(independent_browser).text, 'login-actions/authenticate')
    rejected = client.post(action, data={'username': 'second-user', 'password': 'SecondPassw0rd!'})
    assert rejected.status_code == 400
    assert 'Set-Cookie' not in rejected.headers
    assert client.get_cookie('mini_keycloak_session', path='/realms/demo/') == signed_in_cookie
    with app.app_context():
        sessions = db.session.scalars(select(UserSession)).all()
        assert [(session.id, session.user_id) for session in sessions] == [(existing_id, existing_user_id)]


def test_independent_tabs_complete_and_clear_only_their_own_cookie(app, client):
    first, second = begin(client), begin(client)
    first_cookie, second_cookie = preauth_cookie(first), preauth_cookie(second)
    assert first_cookie is not None and second_cookie is not None
    assert first_cookie.key != second_cookie.key
    for page, cookie in ((first, first_cookie), (second, second_cookie)):
        action = form_action(page.text, 'login-actions/authenticate')
        response = client.post(action, data=CREDENTIALS)
        assert response.status_code == 302 and query_value(response.location, 'code')
        assert client.get_cookie(cookie.key, path=cookie['path']) is None
        cleared = preauth_cookie(response)
        assert cleared is not None and cleared.key == cookie.key and cleared['max-age'] == '0'
        if cookie == first_cookie:
            assert client.get_cookie(second_cookie.key, path=second_cookie['path']) is not None
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 2


def test_invalid_credentials_preserve_binding_for_retry(client):
    page = begin(client)
    cookie = preauth_cookie(page)
    assert cookie is not None
    action = form_action(page.text, 'login-actions/authenticate')
    assert client.post(action, data=CREDENTIALS | {'password': 'incorrect'}).status_code == 401
    assert client.get_cookie(cookie.key, path=cookie['path']).value == cookie.value
    assert client.post(action, data=CREDENTIALS).status_code == 302


def test_concurrent_login_completions_commit_one_session_and_rollback_loser(app, client, monkeypatch):
    barrier = Barrier(2, timeout=10)
    original_get_session = AuthenticationRepository.get_session
    original_add = UserSessionRepository.add
    attempted_sids = []
    committed_counts = []
    synchronized_sessions = set()

    def load_same_version(repository, tab_id):
        session = original_get_session(repository, tab_id)
        assert session.current_execution == 'choose-user'
        # Synchronize only the initial request read. Issuance also revalidates
        # expiry after session insertion, while the writer owns the DB lock.
        if id(session) not in synchronized_sessions:
            synchronized_sessions.add(id(session))
            barrier.wait()
        return session

    monkeypatch.setattr(AuthenticationRepository, 'get_session', load_same_version)

    def record_insert(repository, user_session):
        result = original_add(repository, user_session)
        attempted_sids.append(result.sid)
        return result

    monkeypatch.setattr(UserSessionRepository, 'add', record_insert)

    @app.after_request
    def observe_usable_transaction(response):
        # The failed commit leaves SQLAlchemy unusable until explicitly rolled
        # back. Query now so request teardown cannot hide a missing rollback.
        count = db.session.scalar(select(func.count()).select_from(UserSession))
        committed_counts.append((response.status_code, count))
        return response

    page = begin(client)
    action = form_action(page.text, 'login-actions/authenticate')
    cookie = preauth_cookie(page)
    assert cookie is not None
    committed_counts.clear()

    def complete():
        browser = app.test_client()
        browser.set_cookie(cookie.key, cookie.value, path=cookie['path'])
        return browser.post(action, data=CREDENTIALS)

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: complete(), range(2)))
    assert sorted(response.status_code for response in responses) == [302, 400]
    assert len(set(attempted_sids)) == 2
    assert sorted(committed_counts) == [(302, 1), (400, 1)]
    winner = next(response for response in responses if response.status_code == 302)
    loser = next(response for response in responses if response.status_code == 400)
    assert 'Set-Cookie' not in loser.headers
    winner_cookies = SimpleCookie()
    for header in winner.headers.getlist('Set-Cookie'):
        winner_cookies.load(header)
    signed = winner_cookies['mini_keycloak_session'].value
    sid = app.session_interface.get_signing_serializer(app).loads(signed)['sid']
    with app.app_context():
        sessions = db.session.scalars(select(UserSession)).all()
        assert len(sessions) == 1 and sessions[0].sid == sid
        auth_session = db.session.get(AuthenticationSession, query_value(action, 'tab_id'))
        assert auth_session.current_execution == 'authenticated'
        assert auth_session.selected_user_id == sessions[0].user_id
        assert auth_session.version == 2
        codes = db.session.scalars(select(AuthorizationCode)).all()
        assert len(codes) == 1
        assert codes[0].code_hash == hashlib.sha256(query_value(winner.location, 'code').encode()).hexdigest()
