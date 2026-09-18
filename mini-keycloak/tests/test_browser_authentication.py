from datetime import timedelta

import pytest
from sqlalchemy import func, select

from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationSession, Client, Realm, User, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.identity import IdentityRepository
from tests.helpers import form_action, query_value


AUTH = '/realms/demo/protocol/openid-connect/auth'
PARAMS = dict(client_id='demo-app', redirect_uri='http://localhost:9999/callback',
              response_type='code', scope='openid profile email', state='opaque & state',
              nonce='nonce-value', code_challenge='A' * 43, code_challenge_method='S256')


@pytest.fixture(autouse=True)
def require_pkce_for_browser_tests(app):
    # Browser protocol tests explicitly choose a mandatory-PKCE client,
    # independent of the bundled environment client's bootstrap configuration.
    with app.app_context():
        db.session.scalar(select(Client)).pkce_policy = 'S256'
        db.session.commit()


def begin(client, **overrides):
    return client.get(AUTH, query_string=PARAMS | overrides)


def login(client):
    action = form_action(begin(client).text, 'login-actions/authenticate')
    return client.post(action, data={'username': 'demo-user', 'password': 'DemoPassw0rd!'})


@pytest.mark.parametrize('changes', [
    {'response_type': 'token'}, {'response_type': ''}, {'scope': ''},
    {'scope': 'profile'}, {'scope': 'openid admin'},
    {'redirect_uri': 'http://localhost:9999/callback/extra'},
    {'code_challenge': ''}, {'code_challenge': 'short'},
    {'code_challenge': '!' * 43}, {'code_challenge': 'A' * 44},
    {'code_challenge_method': 'plain'}, {'code_challenge_method': ''},
])
def test_invalid_authorization_does_not_create_session(app, client, changes):
    response = begin(client, **changes)
    if 'redirect_uri' in changes:
        assert response.status_code == 400
        assert 'Location' not in response.headers
    else:
        assert response.status_code == 302
        assert query_value(response.location, 'error') == 'invalid_request'
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(AuthenticationSession)) == 0


def test_duplicate_security_parameter_rejected(client):
    assert client.get(AUTH, query_string=list(PARAMS.items()) + [('client_id', 'other')]).status_code == 400


def test_authorization_persists_oidc_parameters_and_escaped_template(app, client):
    with app.app_context():
        db.session.scalar(select(Realm)).display_name = '<script>alert(1)</script>'
        db.session.commit()
    response = begin(client)
    action = form_action(response.text, 'login-actions/authenticate')
    assert query_value(action, 'client_id') == 'demo-app'
    assert query_value(action, 'execution') == 'login'
    assert '<script>' not in response.text
    assert '&lt;script&gt;' in response.text
    assert 'login-actions/reset-credentials?' in response.text
    with app.app_context():
        session = db.session.get(AuthenticationSession, query_value(action, 'tab_id'))
        for name in ('redirect_uri', 'response_type', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method'):
            assert getattr(session, name) == PARAMS[name]


@pytest.mark.parametrize('username,password', [('missing', 'wrong'), ('demo-user', 'wrong')])
def test_bad_credentials_return_same_public_error(app, client, username, password):
    action = form_action(begin(client).text, 'login-actions/authenticate')
    response = client.post(action, data=dict(username=username, password=password))
    assert response.status_code == 401
    assert 'Invalid username or password.' in response.text
    assert 'Set-Cookie' not in response.headers
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 0


@pytest.mark.parametrize('disabled', ['realm', 'client', 'user', 'standard_flow'])
def test_disabled_entities_rejected_at_login(app, client, disabled):
    action = form_action(begin(client).text, 'login-actions/authenticate')
    with app.app_context():
        model = {'realm': Realm, 'client': Client, 'user': User, 'standard_flow': Client}[disabled]
        entity = db.session.scalar(select(model))
        setattr(entity, 'standard_flow_enabled' if disabled == 'standard_flow' else 'enabled', False)
        db.session.commit()
    response = client.post(action, data=dict(username='demo-user', password='DemoPassw0rd!'))
    if disabled == 'standard_flow':
        assert response.status_code == 302
        assert query_value(response.location, 'error') == 'unauthorized_client'
    else:
        assert response.status_code in (400, 401, 404)
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 0


@pytest.mark.parametrize('mutation', ['expired', 'client', 'realm', 'execution'])
def test_invalid_login_transaction_rejected(app, client, mutation):
    action = form_action(begin(client).text, 'login-actions/authenticate')
    if mutation == 'expired':
        with app.app_context():
            db.session.get(AuthenticationSession, query_value(action, 'tab_id')).expires_at = utc_now() - timedelta(seconds=1)
            db.session.commit()
    elif mutation == 'realm':
        action = action.replace('/realms/demo/', '/realms/absent/')
    elif mutation == 'client':
        action = action.replace('client_id=demo-app', 'client_id=other')
    else:
        action = action.replace('execution=login', 'execution=other')
    assert client.post(action, data=dict(username='demo-user', password='DemoPassw0rd!')).status_code in (400, 404)


def test_successful_login_creates_session_and_cannot_be_replayed(app, client):
    action = form_action(begin(client).text, 'login-actions/authenticate')
    response = client.post(action, data=dict(username='demo-user', password='DemoPassw0rd!'))
    assert response.status_code == 302
    assert query_value(response.location, 'code')
    assert client.post(action, data=dict(username='demo-user', password='DemoPassw0rd!')).status_code == 400
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        assert session.user_id == db.session.scalar(select(User.id))
        assert session.auth_time <= utc_now() < session.idle_expires_at <= session.max_expires_at


@pytest.mark.parametrize('bad_request', [False, True])
def test_authentication_pages_have_security_headers(client, bad_request):
    response = begin(client, scope='' if bad_request else 'openid')
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['Content-Security-Policy'] == "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['Referrer-Policy'] == 'no-referrer'


def test_optional_pkce_accepts_no_challenge_but_rejects_plain(app, client):
    with app.app_context():
        db.session.scalar(select(Client)).pkce_policy = 'optional'
        db.session.commit()
    params = {key: value for key, value in PARAMS.items() if not key.startswith('code_challenge')}
    assert client.get(AUTH, query_string=params).status_code == 200
    assert query_value(begin(client, code_challenge_method='plain').location, 'error') == 'invalid_request'


def test_server_unsupported_scope_is_rejected_even_if_client_allows_it(app, client):
    with app.app_context():
        db.session.scalar(select(Client)).optional_scopes = ['admin']
        db.session.commit()
    assert query_value(begin(client, scope='openid admin').location, 'error') == 'invalid_request'


def test_client_creation_can_explicitly_choose_optional_pkce(app, client):
    with app.app_context():
        realm = db.session.scalar(select(Realm))
        repository = IdentityRepository(db.session)
        created = repository.create_client(realm.id, 'optional-app',
            redirect_uris=['https://example.test/cb'], pkce_policy='optional')
        db.session.commit()
        assert created.pkce_policy == 'optional'
    assert client.get(AUTH, query_string=dict(client_id='optional-app',
        redirect_uri='https://example.test/cb', response_type='code', scope='openid')).status_code == 200


@pytest.mark.parametrize('policy', ['', 'plain', 'disabled'])
def test_client_creation_rejects_unknown_pkce_policy(app, policy):
    with app.app_context():
        realm = db.session.scalar(select(Realm))
        with pytest.raises(ValueError):
            IdentityRepository(db.session).create_client(realm.id, 'bad-policy',
                redirect_uris=['https://example.test/cb'], pkce_policy=policy)


def test_unsupported_prompt_is_rejected_instead_of_silently_ignored(client):
    assert query_value(begin(client, prompt='none').location, 'error') == 'invalid_request'
