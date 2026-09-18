from datetime import timedelta

import pytest
from sqlalchemy import func, select

from mini_keycloak.app import create_app
from mini_keycloak.extensions import db
from mini_keycloak.models import Client, Realm, User, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.sessions import UserSessionService
from tests.helpers import query_value
from tests.test_browser_authentication import begin, login


@pytest.mark.parametrize('secure', [False, True])
def test_browser_cookie_contains_only_signed_opaque_sid(app, client, secure):
    app.config['SESSION_COOKIE_SECURE'] = secure
    response = login(client)
    cookie = response.headers['Set-Cookie']
    assert 'HttpOnly' in cookie and 'SameSite=Lax' in cookie
    assert 'Path=/realms/demo/' in cookie
    assert ('; Secure' in cookie) is secure
    value = cookie.split(';', 1)[0].split('=', 1)[1]
    payload = app.session_interface.get_signing_serializer(app).loads(value)
    with app.app_context():
        assert payload == {'sid': db.session.scalar(select(UserSession.sid))}


def test_browser_session_survives_application_restart(app, client):
    login(client)
    cookies = client.get_cookie('mini_keycloak_session', path='/realms/demo/')
    assert cookies is not None
    restarted = create_app(dict(app.config))
    browser = restarted.test_client()
    browser.set_cookie(cookies.key, cookies.value, path=cookies.path)
    response = begin(browser)
    assert response.status_code == 302
    assert '<form' not in response.text
    assert query_value(response.location, 'code')
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 1


@pytest.mark.parametrize('invalid', ['idle', 'max', 'revoked', 'realm', 'user', 'client', 'cross-realm'])
def test_ineligible_browser_session_never_skips_login(app, client, invalid):
    login(client)
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        if invalid in ('idle', 'max'):
            setattr(session, f'{invalid}_expires_at', utc_now() - timedelta(seconds=1))
        elif invalid == 'revoked':
            session.revoked_at = utc_now()
        elif invalid == 'cross-realm':
            other = Realm(name='other')
            db.session.add(other)
            db.session.flush()
            session.realm_id = other.id
        else:
            db.session.scalar(select({'realm': Realm, 'user': User, 'client': Client}[invalid])).enabled = False
        db.session.commit()
    response = begin(client)
    assert 'Signed in' not in response.text
    assert response.status_code in (200, 400, 404)


def test_tampered_cookie_never_skips_login(app, client):
    login(client)
    cookie = client.get_cookie('mini_keycloak_session', path='/realms/demo/')
    client.set_cookie(cookie.key, cookie.value + 'tampered', path=cookie.path)
    assert '<form' in begin(client).text


def test_realm_lifetimes_override_defaults_and_reuse_extends_idle_only(app, client):
    app.config.update(SSO_IDLE_LIFETIME_SECONDS=99, SSO_MAX_LIFETIME_SECONDS=199)
    with app.app_context():
        realm = db.session.scalar(select(Realm))
        realm.sso_idle_lifetime_seconds = 10
        realm.sso_max_lifetime_seconds = 20
        db.session.commit()
    login(client)
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        assert session.idle_expires_at - session.auth_time == timedelta(seconds=10)
        assert session.max_expires_at - session.auth_time == timedelta(seconds=20)
        auth_time, maximum = session.auth_time, session.max_expires_at
        session.idle_expires_at = utc_now() + timedelta(seconds=1)
        db.session.commit()
    assert query_value(begin(client).location, 'code')
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        assert session.auth_time == auth_time and session.max_expires_at == maximum
        assert session.idle_expires_at > utc_now() + timedelta(seconds=8)


def test_configured_default_lifetimes_are_used(app, client):
    app.config.update(SSO_IDLE_LIFETIME_SECONDS=50, SSO_MAX_LIFETIME_SECONDS=40)
    login(client)
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        assert session.max_expires_at - session.auth_time == timedelta(seconds=40)
        assert session.idle_expires_at == session.max_expires_at


def test_realm_session_can_be_reused_by_another_enabled_client(app, client):
    assert login(client).status_code == 302
    with app.app_context():
        realm = db.session.scalar(select(Realm))
        IdentityRepository(db.session).create_client(realm.id, 'second-app',
            redirect_uris=['https://second.example/callback'])
        db.session.commit()
    response = begin(client, client_id='second-app', redirect_uri='https://second.example/callback')
    assert query_value(response.location, 'code')
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 1


@pytest.mark.parametrize('mismatch', ['user', 'client'])
def test_session_service_rejects_cross_realm_identity(app, mismatch):
    with app.app_context():
        realm = db.session.scalar(select(Realm))
        user = db.session.scalar(select(User))
        client = db.session.scalar(select(Client))
        repository = IdentityRepository(db.session)
        other = repository.create_realm('other')
        if mismatch == 'user':
            user = repository.create_user(other.id, 'other-user', None, 'Password!')
        else:
            client = repository.create_client(other.id, 'other-client', redirect_uris=[])
        service = UserSessionService(db.session, idle_seconds=10, max_seconds=20)
        with pytest.raises(ValueError):
            service.create(realm, client, user)
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 0
