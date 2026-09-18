from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pytest
from sqlalchemy import select
from sqlalchemy.exc import StatementError

from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationSession, Client, Realm, UserSession
from tests.helpers import form_action
from tests.test_authorization_code import AUTH, PARAMS, issue
from tests.test_client_authentication import TOKEN


@pytest.fixture
def realm_host_app(monkeypatch, request):
    # Realm issuer overrides do not implicitly expand the deployment Host policy.
    monkeypatch.setenv('MINI_KEYCLOAK_TRUSTED_HOSTS',
                       'localhost,127.0.0.1,[::1],realm.example.test')
    return request.getfixturevalue('app')


@pytest.mark.parametrize('headers', [
    {'Origin': 'https://untrusted.test'}, {'Origin': 'null'},
    {'Origin': 'http://127.0.0.1:5000/path'}, {'Origin': 'http://127.0.0.1:5000 https://evil.test'},
    {'Sec-Fetch-Site': 'cross-site'}, {'Sec-Fetch-Site': 'same-site'},
    {'Origin': 'http://127.0.0.1:5000', 'Sec-Fetch-Site': 'cross-site'},
])
def test_authenticate_rejects_untrusted_browser_origin_without_consuming_login(client, headers):
    action = form_action(client.get(AUTH, query_string=PARAMS).text, 'authenticate')
    data = dict(username='demo-user', password='DemoPassw0rd!')
    assert client.post(action, data=data, headers=headers).status_code == 400
    assert client.post(action, data=data).status_code == 302


@pytest.mark.parametrize('headers', [{}, {'Sec-Fetch-Site': 'same-origin'},
    {'Origin': 'http://127.0.0.1:5000'},
    {'Origin': 'http://127.0.0.1:5000', 'Sec-Fetch-Site': 'same-origin'}])
def test_authenticate_allows_configured_origin_and_nonbrowser_clients(client, headers):
    action = form_action(client.get(AUTH, query_string=PARAMS).text, 'authenticate')
    assert client.post(action, data=dict(username='demo-user', password='DemoPassw0rd!'),
                       headers=headers).status_code == 302


@pytest.mark.parametrize('issuer, origin', [
    ('https://realm.example.test/realms/demo', 'https://realm.example.test'),
    ('https://REALM.example.test:443/realms/demo', 'https://realm.example.test'),
    ('https://realm.example.test/realms/demo', 'https://REALM.example.test:443'),
    ('http://realm.example.test:80/realms/demo', 'http://realm.example.test'),
    ('https://realm.example.test:8443/realms/demo', 'https://realm.example.test:8443'),
    ('https://[::1]:8443/realms/demo', 'https://[::1]:8443'),
])
def test_authenticate_uses_canonical_realm_issuer_origin(realm_host_app, issuer, origin):
    app = realm_host_app
    with app.app_context():
        db.session.scalar(select(Realm)).issuer_override = issuer
        db.session.commit()
    browser = app.test_client()
    metadata = browser.get('/realms/demo/.well-known/openid-configuration').json
    assert metadata['issuer'] == issuer
    page = browser.get(metadata['authorization_endpoint'], query_string=PARAMS)
    assert page.status_code == 200
    action = form_action(page.text, 'authenticate')
    external = urlsplit(issuer)
    response = browser.post(action, base_url=f'{external.scheme}://{external.netloc}', headers={
        'Origin': origin, 'Sec-Fetch-Site': 'same-origin'},
        data={'username': 'demo-user', 'password': 'DemoPassw0rd!'})
    assert response.status_code == 302
    with app.app_context():
        assert db.session.scalar(select(UserSession)) is not None


@pytest.mark.parametrize('origin', [
    'http://127.0.0.1:5000', 'https://foreign.example.test',
    'http://realm.example.test', 'https://realm.example.test:8443',
    'null', '', 'https://realm.example.test/', 'https://realm.example.test/path',
    'https://realm.example.test?', 'https://realm.example.test#',
    'https://realm.example.test:bad', 'https://realm.example.test:',
    'https://user@realm.example.test', 'https://realm.example.test@foreign.test',
    'https://realm.example.test https://foreign.test', 'https://realm.example.test,https://foreign.test',
    'https://realm.example.test\\@foreign.test', 'https://[invalid]',
])
def test_realm_override_rejects_global_foreign_and_malformed_origins(app, client, origin):
    with app.app_context():
        db.session.scalar(select(Realm)).issuer_override = 'https://realm.example.test/realms/demo'
        db.session.commit()
    action = form_action(client.get(AUTH, query_string=PARAMS).text, 'authenticate')
    response = client.post(action, headers={'Origin': origin, 'Sec-Fetch-Site': 'same-origin'},
        data={'username': 'demo-user', 'password': 'DemoPassw0rd!'})
    assert response.status_code == 400
    with app.app_context():
        assert db.session.scalar(select(UserSession)) is None
    assert client.post(action, headers={'Origin': 'https://realm.example.test'},
        data={'username': 'demo-user', 'password': 'DemoPassw0rd!'}).status_code == 302


def test_global_origin_fallback_compares_canonical_origin_only(app, client):
    app.config['EXTERNAL_URL'] = 'https://GLOBAL.example.test:443/prefix'
    action = form_action(client.get(AUTH, query_string=PARAMS).text, 'authenticate')
    assert client.post(action, headers={'Origin': 'https://global.example.test'},
        data={'username': 'demo-user', 'password': 'DemoPassw0rd!'}).status_code == 302


@pytest.mark.parametrize('path', [TOKEN, '/realms/demo/protocol/openid-connect/userinfo',
                                '/realms/demo/protocol/openid-connect/logout'])
def test_oversized_ordinary_requests_return_bounded_safe_json(client, path):
    response = client.post(path, data='password=' + 'x' * 70000,
                           content_type='application/x-www-form-urlencoded')
    assert response.status_code == 413
    assert response.json == {'error': 'invalid_request'}
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'


def test_oversized_authenticate_returns_safe_html(client):
    action = form_action(client.get(AUTH, query_string=PARAMS).text, 'authenticate')
    response = client.post(action, data={'username': 'demo-user', 'password': 'x' * 70000})
    assert response.status_code == 413
    assert 'x' * 100 not in response.text
    assert response.headers['X-Frame-Options'] == 'DENY'


@pytest.mark.parametrize('authorization', ['Basic !!!', 'Basic', 'Bearer raw-secret'])
def test_malformed_client_authentication_is_safe_and_nosniff(client, authorization):
    response = client.post(TOKEN, data={'grant_type': 'password'}, headers={'Authorization': authorization})
    assert response.status_code == 401
    assert response.json == {'error': 'invalid_client'}
    assert response.headers['X-Content-Type-Options'] == 'nosniff'


def test_unexpected_browser_failure_returns_generic_html_and_rolls_back(app, client, monkeypatch, caplog):
    from mini_keycloak.services.authorization import AuthorizationService
    def fail(*args, **kwargs):
        raise RuntimeError('password-private-secret')
    monkeypatch.setattr(AuthorizationService, 'issue', fail)
    response = issue(client)
    assert response.status_code == 500
    assert 'password-private-secret' not in response.text + caplog.text
    with app.app_context():
        assert db.session.scalar(select(UserSession)) is None


def test_protocol_timestamp_normalizes_nonzero_offset_without_changing_instant(app, client):
    issue(client)
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        session.revoked_at = datetime(2026, 9, 18, 8, 15, tzinfo=timezone(timedelta(hours=-3)))
        db.session.commit()
        db.session.expire_all()
        assert session.revoked_at == datetime(2026, 9, 18, 11, 15, tzinfo=timezone.utc)
        assert session.revoked_at.utcoffset() == timedelta(0)


def test_protocol_timestamp_rejects_naive_input(app, client):
    issue(client)
    with app.app_context():
        db.session.scalar(select(UserSession)).revoked_at = datetime(2026, 9, 18, 8, 15)
        with pytest.raises(StatementError, match='timezone-aware'):
            db.session.commit()
        db.session.rollback()


def test_login_rejects_persisted_client_relationship_from_another_realm(app, client):
    action = form_action(client.get(AUTH, query_string=PARAMS).text, 'authenticate')
    with app.app_context():
        other = Realm(name='other')
        db.session.add(other)
        db.session.flush()
        wrong_client = Client(realm_id=other.id, client_id='demo-app', redirect_uris=[PARAMS['redirect_uri']])
        db.session.add(wrong_client)
        db.session.flush()
        db.session.scalar(select(AuthenticationSession)).client_id = wrong_client.id
        db.session.commit()
    response = client.post(action, data=dict(username='demo-user', password='DemoPassw0rd!'))
    assert response.status_code == 400
    with app.app_context():
        assert db.session.scalar(select(UserSession)) is None
