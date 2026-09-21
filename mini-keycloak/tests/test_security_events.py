import json

import pytest
from sqlalchemy import select

from mini_keycloak.extensions import db
from mini_keycloak.models import Client, Realm, SecurityEvent, UserSession
from tests.helpers import form_action
from tests.test_authorization_code import AUTH, PARAMS, issue, returned_code
from tests.test_token_endpoint import exchange
from tests.test_client_authentication import TOKEN


def events(app):
    with app.app_context():
        return [dict(type=e.event_type, realm=e.realm_id, client=e.client_id,
                     user=e.user_id, session=e.user_session_id, error=e.error,
                     details=e.details, source=e.source_address, time=e.created_at.isoformat())
                for e in db.session.scalars(select(SecurityEvent).order_by(SecurityEvent.created_at))]


def test_login_exchange_refresh_reuse_and_logout_are_audited_without_secrets(app, client):
    action = form_action(client.get(AUTH, query_string=PARAMS).text, 'authenticate')
    assert client.post(action, data=dict(username='unknown-secret', password='password-secret')).status_code == 401
    raw = returned_code(issue(client))
    tokens = exchange(client, raw).json
    assert exchange(client, raw).status_code == 400
    refresh = dict(grant_type='refresh_token', client_id='demo-app', refresh_token=tokens['refresh_token'])
    assert client.post(TOKEN, data=refresh).status_code == 200
    assert client.post(TOKEN, data=refresh).status_code == 400
    # A separate browser session exercises a successful logout after reuse revocation.
    other = app.test_client()
    other_tokens = exchange(other, returned_code(issue(other))).json
    assert other.get('/realms/demo/protocol/openid-connect/logout', query_string={
        'id_token_hint': other_tokens['id_token']}).status_code == 200
    rows = events(app)
    assert {'LOGIN_ERROR', 'LOGIN', 'CODE_TO_TOKEN', 'CODE_TO_TOKEN_ERROR',
            'REFRESH_TOKEN', 'REFRESH_TOKEN_REUSE', 'LOGOUT'} <= {e['type'] for e in rows}
    assert all(e['realm'] and e['time'].endswith('+00:00') and e['source'] == '127.0.0.1' for e in rows)
    assert all(e['user'] and e['session'] and e['client'] for e in rows if e['type'] in {
        'LOGIN', 'CODE_TO_TOKEN', 'REFRESH_TOKEN', 'REFRESH_TOKEN_REUSE', 'LOGOUT'})
    serialized = json.dumps(rows)
    for secret in ['unknown-secret', 'password-secret', 'DemoPassw0rd!', raw,
                   tokens['access_token'], tokens['refresh_token'], tokens['id_token'],
                   PARAMS['nonce'], PARAMS['state']]:
        assert secret not in serialized


def test_password_grant_failure_and_logout_failure_are_audited(app, client):
    data = dict(grant_type='password', client_id='demo-app', username='demo-user', password='wrong-secret')
    assert client.post(TOKEN, data=data).status_code == 400
    assert client.post(TOKEN, data=data | {'password': 'DemoPassw0rd!'}).status_code == 200
    assert client.get('/realms/demo/protocol/openid-connect/logout', query_string={
        'id_token_hint': 'raw-token-secret'}).status_code == 401
    rows = events(app)
    assert {'PASSWORD_GRANT_ERROR', 'PASSWORD_GRANT', 'LOGOUT_ERROR'} <= {e['type'] for e in rows}
    assert 'wrong-secret' not in json.dumps(rows)
    assert 'raw-token-secret' not in json.dumps(rows)


def test_event_service_projects_safe_values_and_rejects_cross_realm_references(app):
    from mini_keycloak.services.events import EventService
    with app.app_context():
        realm = db.session.scalar(select(Realm))
        client = db.session.scalar(select(Client))
        event = EventService(db.session).record(realm.id, 'LOGIN_ERROR', client_id=client.id,
            source_address='untrusted-secret', error='password-secret', details={
                'grant_type': 'password', 'auth_method': 'client_secret_post',
                'password': 'password-secret', 'token': 'token-secret',
                'nested': {'cookie': 'cookie-secret'}, 'reason': 'x' * 10000})
        db.session.commit()
        assert event.details == {'grant_type': 'password', 'auth_method': 'client_secret_post'}
        assert event.source_address is None
        assert event.error == 'invalid_request'
        other = Realm(name='other')
        db.session.add(other)
        db.session.flush()
        with pytest.raises(ValueError):
            EventService(db.session).record(other.id, 'LOGIN', client_id=client.id)
        with pytest.raises(ValueError):
            EventService(db.session).record(realm.id, 'raw-token-secret')


def test_failed_signing_does_not_commit_success_event(app, client, monkeypatch):
    from mini_keycloak.services.tokens import TokenService
    raw = returned_code(issue(client))
    def fail(*args, **kwargs):
        raise RuntimeError('private-key-secret')
    monkeypatch.setattr(TokenService, 'issue', fail)
    assert exchange(client, raw).status_code == 500
    rows = events(app)
    assert not any(e['type'] == 'CODE_TO_TOKEN' for e in rows)
    assert any(e['type'] == 'CODE_TO_TOKEN_ERROR' and e['error'] == 'server_error' for e in rows)
    assert 'private-key-secret' not in json.dumps(rows)


def test_rejected_browser_binding_records_failure_without_request_values(app, client):
    action = form_action(client.get(AUTH, query_string=PARAMS).text, 'authenticate')
    assert client.post(action, data=dict(username='private-user', password='private-password'),
                       headers={'Origin': 'https://untrusted.test'}).status_code == 400
    rows = events(app)
    assert [row['type'] for row in rows] == ['LOGIN_ERROR']
    assert rows[0]['user'] is None and rows[0]['session'] is None
    assert 'private-' not in json.dumps(rows)


def test_event_storage_failure_rolls_back_issuance_and_never_logs_exception_values(app, client, monkeypatch, caplog):
    from mini_keycloak.models import AuthorizationCode, RefreshToken
    from mini_keycloak.repositories.events import EventRepository
    raw = returned_code(issue(client))
    def fail(*args, **kwargs):
        raise RuntimeError('sql-parameter-private-secret')
    monkeypatch.setattr(EventRepository, 'add', fail)
    response = exchange(client, raw)
    assert response.status_code == 500
    assert response.json == {'error': 'server_error'}
    assert 'sql-parameter-private-secret' not in caplog.text + response.text
    with app.app_context():
        assert db.session.scalar(select(AuthorizationCode)).consumed_at is None
        assert db.session.scalar(select(RefreshToken)) is None


@pytest.mark.parametrize('database_error', [False, True])
def test_reuse_still_revokes_session_if_audit_write_fails(app, client, monkeypatch, caplog, database_error):
    from mini_keycloak.models import RefreshToken
    from mini_keycloak.repositories.events import EventRepository
    tokens = exchange(client, returned_code(issue(client))).json
    data = dict(grant_type='refresh_token', client_id='demo-app', refresh_token=tokens['refresh_token'])
    assert client.post(TOKEN, data=data).status_code == 200
    def fail(*args, **kwargs):
        if database_error:
            db.session.add(SecurityEvent(realm_id='nonexistent-realm', event_type='LOGIN'))
            db.session.flush()
        raise RuntimeError('event-storage-private-secret')
    monkeypatch.setattr(EventRepository, 'add', fail)
    response = client.post(TOKEN, data=data)
    assert (response.status_code, response.json) == (400, {'error': 'invalid_grant'})
    with app.app_context():
        assert db.session.scalar(select(UserSession)).revoked_at is not None
        assert all(row.revoked_at is not None for row in db.session.scalars(select(RefreshToken)))
    assert 'event-storage-private-secret' not in caplog.text + response.text


@pytest.mark.parametrize('event_type', ['SEND_RESET_PASSWORD', 'UPDATE_PASSWORD', 'UPDATE_CREDENTIAL'])
def test_reset_events_project_persisted_identity_and_session_only(app, event_type):
    from mini_keycloak.repositories.authentication import AuthenticationRepository
    from mini_keycloak.repositories.identity import IdentityRepository
    from mini_keycloak.services.events import EventService
    with app.app_context():
        identities = IdentityRepository(db.session)
        realm = identities.get_realm('demo')
        client = identities.get_client(realm.id, 'demo-app')
        user = identities.find_user(realm.id, 'demo-user')
        auth = AuthenticationRepository(db.session).create_session(realm, client, client.redirect_uris[0], 'account')
        auth.selected_user_id = user.id
        event = EventService(db.session).record(realm.id, event_type, client_id=client.id,
            user_id=user.id, authentication_session_id=auth.tab_id,
            details={'code_id': 'request-value', 'username': 'request-value', 'email': 'request-value'})
        assert event.details == {'code_id': auth.tab_id, 'username': user.username, 'email': user.email}
        with pytest.raises(ValueError):
            EventService(db.session).record(realm.id, event_type, client_id=client.id,
                user_id=user.id, authentication_session_id='missing')
        other = identities.create_user(realm.id, 'other', 'other@example.test', 'ExamplePassw0rd!')
        with pytest.raises(ValueError):
            EventService(db.session).record(realm.id, event_type, client_id=client.id,
                user_id=other.id, authentication_session_id=auth.tab_id)
        ordinary = EventService(db.session).record(realm.id, 'LOGIN', client_id=client.id,
            user_id=user.id, details={'code_id': 'request-value', 'username': 'request-value', 'email': 'request-value'})
        assert ordinary.details == {}
