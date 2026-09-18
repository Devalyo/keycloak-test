import importlib
import json
import re

import pytest
from sqlalchemy import select
from werkzeug.exceptions import BadRequest, InternalServerError, RequestEntityTooLarge

from mini_keycloak.extensions import db
from mini_keycloak.models import Realm, SecurityEvent, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.keys import RealmKeyService
from mini_keycloak.services.tokens import TokenService
from tests.test_authorization_code import AUTH, PARAMS
from tests.test_client_authentication import TOKEN
from tests.test_jwt_tokens import issued
from tests.test_logout import LOGOUT
from tests.test_oidc_discovery import CERTS, DISCOVERY
from tests.test_userinfo import USERINFO, bearer


SECRET = 'exception-and-sql-parameter-private-sentinel'
REQUEST_SECRETS = ['raw-code-secret', 'cookie-secret', 'form-password-secret']
SAFE_LOG = re.compile(
    r'(?:OIDC request failed unexpectedly|Token request failed unexpectedly|'
    r'Logout request failed unexpectedly|Browser request failed unexpectedly|'
    r'Security event persistence failed)'
)


def assert_redacted_logs(caplog, *secrets):
    assert caplog.records
    for record in caplog.records:
        assert record.exc_info is None and record.exc_text is None
        assert record.stack_info is None
        assert SAFE_LOG.fullmatch(record.getMessage())
        assert re.fullmatch('[0-9a-f]{32}', getattr(record, 'request_id', ''))
    for secret in (SECRET, *REQUEST_SECRETS, *secrets):
        if isinstance(secret, str):
            assert secret not in caplog.text


def assert_server_error(response):
    assert (response.status_code, response.json) == (500, {'error': 'server_error'})
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert 'Location' not in response.headers
    for secret in (SECRET, *REQUEST_SECRETS):
        assert secret not in response.text


@pytest.mark.parametrize('testing', [False, True])
@pytest.mark.parametrize('failure', ['runtime', 'database'])
@pytest.mark.parametrize('endpoint', ['discovery', 'jwks', 'userinfo', 'userinfo_lookup', 'token', 'browser'])
def test_ordinary_unexpected_failures_rollback_and_never_log_exception_values(
        app, client, monkeypatch, caplog, testing, failure, endpoint):
    tokens = issued(client)
    app.config.update(TESTING=testing, PROPAGATE_EXCEPTIONS=testing)
    client.set_cookie('sentinel', REQUEST_SECRETS[1])

    def fail(*args, **kwargs):
        realm = db.session.scalar(select(Realm))
        realm.display_name = 'must-be-rolled-back'
        db.session.flush()
        if failure == 'database':
            # A real failed SQL flush includes the sentinel among SQL parameters.
            db.session.add(Realm(name=realm.name, display_name=SECRET))
            db.session.flush()
        raise RuntimeError(SECRET)

    target, attribute = {
        'discovery': (IdentityRepository, 'get_realm'),
        'jwks': (RealmKeyService, 'public_jwks'),
        'userinfo': (TokenService, 'userinfo'),
        'userinfo_lookup': (IdentityRepository, 'get_realm'),
        'token': (TokenService, 'password_grant'),
        'browser': (IdentityRepository, 'get_realm'),
    }[endpoint]
    monkeypatch.setattr(target, attribute, fail)
    with app.app_context():
        original = db.session.scalar(select(Realm.display_name))
        if endpoint == 'token':
            response = client.post(TOKEN, data=dict(grant_type='password', client_id='demo-app',
                username='demo-user', password=REQUEST_SECRETS[2], code=REQUEST_SECRETS[0]))
        else:
            path = dict(discovery=DISCOVERY, jwks=CERTS, userinfo=USERINFO,
                        userinfo_lookup=USERINFO, browser=AUTH)[endpoint]
            response = client.get(path, headers=bearer(tokens['access_token']),
                                  query_string=PARAMS | {'code': REQUEST_SECRETS[0]})
        if endpoint == 'browser':
            assert response.status_code == 500 and response.mimetype == 'text/html'
            assert response.headers['Cache-Control'] == 'no-store'
            assert response.headers['X-Content-Type-Options'] == 'nosniff'
        else:
            assert_server_error(response)
        # Keep the request's session alive: teardown must not hide missing rollback.
        assert db.session.is_active
        assert db.session.scalar(select(Realm.display_name)) == original
    assert_redacted_logs(caplog, *tokens.values())
    assert {record.request_id for record in caplog.records} == {response.headers['X-Request-ID']}


@pytest.mark.parametrize('failure', ['runtime', 'database'])
@pytest.mark.parametrize('audit_failure', [None, 'runtime', 'database'])
def test_unexpected_logout_audits_after_rollback_and_preserves_safe_response(
        app, client, monkeypatch, caplog, failure, audit_failure):
    from mini_keycloak.services.events import EventService

    tokens = issued(client)
    module = importlib.import_module('mini_keycloak.oidc.logout')

    def fail_revoke(session, sid, realm_id):
        session.scalar(select(UserSession).where(UserSession.sid == sid)).revoked_at = utc_now()
        session.flush()
        if failure == 'database':
            session.add(Realm(name='demo', display_name=SECRET))
            session.flush()
        raise RuntimeError(SECRET)

    if audit_failure:
        def fail_audit(service, *args, **kwargs):
            if audit_failure == 'database':
                service.session.add(Realm(name='demo', display_name=SECRET))
                service.session.flush()
            raise RuntimeError(SECRET)
        monkeypatch.setattr(EventService, 'record', fail_audit)
    monkeypatch.setattr(module, 'revoke_session', fail_revoke)
    with app.app_context():
        response = client.post(LOGOUT, data={'id_token_hint': tokens['id_token'],
            'post_logout_redirect_uri': 'https://untrusted.test', 'state': REQUEST_SECRETS[0]})
        assert_server_error(response)
        assert 'Set-Cookie' not in response.headers
        assert db.session.is_active
        assert db.session.scalar(select(UserSession.revoked_at)) is None
        events = db.session.scalars(select(SecurityEvent).where(
            SecurityEvent.event_type.in_(['LOGOUT', 'LOGOUT_ERROR']))).all()
        assert len(events) == (0 if audit_failure else 1)
        if not audit_failure:
            event = events[0]
            assert event.event_type == 'LOGOUT_ERROR' and event.error == 'server_error'
            assert event.details == {}
            serialized = json.dumps({column.name: str(getattr(event, column.name))
                                     for column in SecurityEvent.__table__.columns})
            for secret in (SECRET, tokens['id_token'], *REQUEST_SECRETS):
                assert secret not in serialized
    assert_redacted_logs(caplog, *tokens.values())
    assert {record.request_id for record in caplog.records} == {response.headers['X-Request-ID']}


def test_unexpected_failure_logs_have_generated_unique_correlation_ids(app, client, monkeypatch, caplog):
    def fail(*args):
        raise RuntimeError(SECRET)
    monkeypatch.setattr(IdentityRepository, 'get_realm', fail)
    responses = [client.get(DISCOVERY, headers={'X-Request-ID': SECRET}) for _ in range(2)]
    for response in responses:
        assert_server_error(response)
    assert_redacted_logs(caplog)
    ids = {record.request_id for record in caplog.records}
    assert len(ids) == 2
    assert ids == {response.headers['X-Request-ID'] for response in responses}


@pytest.mark.parametrize('exception,status,error', [
    (BadRequest, 400, 'invalid_request'),
    (RequestEntityTooLarge, 413, 'invalid_request'),
    (InternalServerError, 500, 'server_error'),
])
@pytest.mark.parametrize('path,method', [(DISCOVERY, 'get'), (CERTS, 'get'),
    (USERINFO, 'get'), (TOKEN, 'post'), (LOGOUT, 'post')])
def test_http_error_statuses_survive_ordinary_exception_boundaries(
        client, monkeypatch, caplog, exception, status, error, path, method):
    def fail(*args):
        raise exception(description=SECRET)
    monkeypatch.setattr(IdentityRepository, 'get_realm', fail)
    response = getattr(client, method)(path)
    assert (response.status_code, response.json) == (status, {'error': error})
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert SECRET not in response.text + caplog.text
