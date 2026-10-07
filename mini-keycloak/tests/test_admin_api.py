from datetime import timedelta

import pytest
from sqlalchemy import select

from mini_keycloak.extensions import db
from mini_keycloak.models import (
    AuthorizationCode, Client, Realm, RefreshToken, SecurityEvent, User, UserSession,
)
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.import_export.validation import validate_realm_import
from mini_keycloak.services.realm_import import ClientAlreadyExists, RealmImportError, RealmImportService


ADMIN = '/admin/realms'
PASSWORD = 'AdminPassw0rd!'


@pytest.fixture
def admin_headers(app, client):
    result = app.test_cli_runner().invoke(
        args=['admin-bootstrap', '--username', 'operator'],
        input=f'{PASSWORD}\n{PASSWORD}\n',
    )
    assert result.exit_code == 0, result.output
    response = client.post('/realms/master/protocol/openid-connect/token', data={
        'grant_type': 'password', 'client_id': 'admin-cli',
        'username': 'operator', 'password': PASSWORD,
    })
    assert response.status_code == 200, response.json
    return {'Authorization': 'Bearer ' + response.json['access_token']}


def test_admin_endpoints_require_master_admin_token(app, client, admin_headers):
    assert client.get(ADMIN).status_code == 401
    assert client.get(ADMIN, headers={'Authorization': 'Bearer invalid'}).status_code == 401
    ordinary = client.post('/realms/demo/protocol/openid-connect/token', data={
        'grant_type': 'password', 'client_id': 'demo-app',
        'username': 'demo-user', 'password': 'DemoPassw0rd!',
    }).json['access_token']
    assert client.get(ADMIN, headers={'Authorization': 'Bearer ' + ordinary}).status_code == 401
    with app.app_context():
        operator = IdentityRepository(db.session).find_user(
            IdentityRepository(db.session).get_realm('master').id, 'operator')
        operator.attributes = {}
        db.session.commit()
    assert client.get(ADMIN, headers=admin_headers).status_code == 403


def test_realm_create_list_read_and_update(app, client, admin_headers):
    response = client.post(ADMIN, headers=admin_headers, json={
        'realm': 'workspace', 'displayName': 'Workspace',
        'clients': [{'clientId': 'browser', 'redirectUris': ['https://app.example/callback']}],
    })
    assert response.status_code == 201, response.json
    assert response.headers['Location'].endswith('/admin/realms/workspace')
    listed = client.get(ADMIN, headers=admin_headers)
    assert listed.status_code == 200
    assert listed.headers['Cache-Control'] == 'no-store'
    assert {item['realm'] for item in listed.json} == {'demo', 'master', 'workspace'}
    detail = client.get(ADMIN + '/workspace', headers=admin_headers)
    assert detail.json['displayName'] == 'Workspace'
    assert detail.json['enabled'] is True
    assert client.get(ADMIN + '/workspace/clients', headers=admin_headers).json[0]['clientId'] == 'browser'
    updated = client.put(ADMIN + '/workspace', headers=admin_headers, json={
        'displayName': 'Changed', 'enabled': False,
    })
    assert updated.status_code == 204
    assert client.get(ADMIN + '/workspace', headers=admin_headers).json['displayName'] == 'Changed'
    assert client.get(ADMIN + '/workspace', headers=admin_headers).json['enabled'] is False
    assert client.get(ADMIN + '/workspace/clients', headers=admin_headers).json[0]['clientId'] == 'browser'
    assert client.get('/realms/workspace/.well-known/openid-configuration').status_code == 404


def test_realm_reset_flow_can_be_copied_and_selected(app, client, admin_headers):
    base = ADMIN + '/demo'
    flows = client.get(base + '/authentication/flows', headers=admin_headers)
    assert flows.status_code == 200
    assert [flow['alias'] for flow in flows.json] == ['reset credentials']
    assert flows.json[0]['builtIn'] is True

    source = base + '/authentication/flows/reset%20credentials'
    executions = client.get(source + '/executions', headers=admin_headers)
    assert executions.status_code == 200
    assert [item['providerId'] for item in executions.json] == [
        'reset-credentials-choose-user', 'reset-credential-email', 'reset-password',
    ]

    copied = client.post(source + '/copy', headers=admin_headers,
                         json={'newName': 'alternate reset'})
    assert copied.status_code == 201
    assert client.post(source + '/copy', headers=admin_headers,
                       json={'newName': 'alternate reset'}).status_code == 409

    assert client.put(base, headers=admin_headers,
                      json={'resetCredentialsFlow': 'alternate reset'}).status_code == 204
    detail = client.get(base, headers=admin_headers)
    assert detail.json['resetCredentialsFlow'] == 'alternate reset'
    with app.app_context():
        from mini_keycloak.services.authentication_flows import AuthenticationFlowService
        realm = IdentityRepository(db.session).get_realm('demo')
        assert AuthenticationFlowService(db.session).ensure_reset_flow(realm).alias == 'alternate reset'

    assert client.put(base, headers=admin_headers,
                      json={'resetCredentialsFlow': 'absent'}).status_code == 400
    assert client.get(base, headers=admin_headers).json['resetCredentialsFlow'] == 'alternate reset'


def test_realm_mail_settings_round_trip(app, client, admin_headers):
    path = ADMIN + '/demo'
    settings = {'host': '127.0.0.1', 'port': '1025',
                'from': 'no-reply@example.test'}
    updated = client.put(path, headers=admin_headers,
                         json={'smtpServer': settings})
    assert updated.status_code == 204
    assert client.get(path, headers=admin_headers).json['smtpServer'] == settings

    rejected = client.put(path, headers=admin_headers,
                          json={'smtpServer': {'host': '127.0.0.1', 'port': '0',
                                               'from': 'no-reply@example.test'}})
    assert rejected.status_code == 400
    assert client.get(path, headers=admin_headers).json['smtpServer'] == settings


def test_client_create_list_read_and_update(app, client, admin_headers):
    path = ADMIN + '/demo/clients'
    created = client.post(path, headers=admin_headers, json={
        'clientId': 'scanner', 'redirectUris': ['https://scanner.example/callback'],
        'webOrigins': ['https://scanner.example'],
    })
    assert created.status_code == 201, created.json
    location = created.headers['Location']
    assert location.startswith('http://localhost/admin/realms/demo/clients/')
    listed = client.get(path, headers=admin_headers, query_string={'clientId': 'scanner'})
    assert listed.status_code == 200
    assert len(listed.json) == 1
    assert listed.json[0]['clientId'] == 'scanner'
    assert client.get(location, headers=admin_headers).json['redirectUris'] == ['https://scanner.example/callback']
    changed = client.put(location, headers=admin_headers, json={
        'clientId': 'scanner', 'enabled': False, 'name': 'Scanner app',
    })
    assert changed.status_code == 204
    detail = client.get(location, headers=admin_headers).json
    assert detail['enabled'] is False
    assert detail['name'] == 'Scanner app'
    assert detail['redirectUris'] == ['https://scanner.example/callback']


def test_client_search_and_session_count(app, client, admin_headers):
    path = ADMIN + '/demo/clients'
    for client_id in ('scanner-one', 'scanner-two'):
        assert client.post(path, headers=admin_headers,
                           json={'clientId': client_id}).status_code == 201

    exact = client.get(path, headers=admin_headers,
                       query_string={'clientId': 'scanner'})
    assert exact.json == []
    searched = client.get(path, headers=admin_headers,
                          query_string={'clientId': 'scanner', 'search': 'true'})
    assert [item['clientId'] for item in searched.json] == ['scanner-one', 'scanner-two']
    assert client.get(path, headers=admin_headers,
                      query_string={'search': 'sometimes'}).status_code == 400

    login = client.post('/realms/demo/protocol/openid-connect/token', data={
        'grant_type': 'password', 'client_id': 'demo-app',
        'username': 'demo-user', 'password': 'DemoPassw0rd!',
    })
    assert login.status_code == 200
    original = client.get(path, headers=admin_headers,
                          query_string={'clientId': 'demo-app'}).json[0]
    count = client.get(path + '/' + original['id'] + '/session-count',
                       headers=admin_headers)
    assert count.status_code == 200
    assert count.json == {'count': 1}
    assert client.get(path + '/missing/session-count',
                      headers=admin_headers).status_code == 404


def test_client_attribute_query_and_unpaged_list(app, client, admin_headers):
    path = ADMIN + '/demo/clients'
    with app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.get_realm('demo')
        for index in range(101):
            created = repository.create_client(realm.id, f'app-{index:03d}', redirect_uris=[])
            if index == 0:
                created.post_logout_redirect_uris = ['https://unique.example/logout']
        db.session.commit()

    listed = client.get(path, headers=admin_headers)
    assert listed.status_code == 200
    assert len(listed.json) == 102
    assert len(client.get(path, headers=admin_headers,
                          query_string={'max': '1001'}).json) == 102
    matched = client.get(path, headers=admin_headers,
                         query_string={'q': 'post.logout.redirect.uris:https://unique.example/logout'})
    assert [item['clientId'] for item in matched.json] == ['app-000']


def test_client_session_count_and_deletion_preserve_shared_session(app, client, admin_headers):
    path = ADMIN + '/demo/clients'
    created = client.post(path, headers=admin_headers, json={'clientId': 'second-app'})
    assert created.status_code == 201
    login = client.post('/realms/demo/protocol/openid-connect/token', data={
        'grant_type': 'password', 'client_id': 'demo-app',
        'username': 'demo-user', 'password': 'DemoPassw0rd!',
    })
    assert login.status_code == 200
    with app.app_context():
        realm = IdentityRepository(db.session).get_realm('demo')
        session = db.session.scalar(select(UserSession).where(UserSession.realm_id == realm.id))
        first_id = session.client_id
        db.session.add(AuthorizationCode(
            code_hash='a' * 64, realm_id=session.realm_id,
            client_id=created.json['id'], user_id=session.user_id,
            user_session_id=session.id, redirect_uri='https://second.example/callback',
            scope='openid', expires_at=utc_now() + timedelta(minutes=5),
        ))
        db.session.commit()

    count = client.get(created.headers['Location'] + '/session-count', headers=admin_headers)
    assert count.status_code == 200
    assert count.json == {'count': 1}
    assert client.delete(path + '/' + first_id, headers=admin_headers).status_code == 204
    with app.app_context():
        realm = IdentityRepository(db.session).get_realm('demo')
        session = db.session.scalar(select(UserSession).where(UserSession.realm_id == realm.id))
        assert session.client_id == created.json['id']
        assert db.session.scalar(select(AuthorizationCode).where(
            AuthorizationCode.client_id == created.json['id'])) is not None


def test_admin_rejects_conflicts_invalid_input_and_cross_realm_ids(app, client, admin_headers):
    assert client.post(ADMIN, headers=admin_headers, json={'realm': 'DEMO'}).status_code == 409
    assert client.post(ADMIN, headers=admin_headers, json={'realm': 'bad/name'}).status_code == 400
    assert client.post(ADMIN + '/demo/clients', headers=admin_headers,
                       json={'clientId': 'DEMO-APP'}).status_code == 409
    assert client.post(ADMIN + '/demo/clients', headers=admin_headers,
                       json={'clientId': 'bad', 'redirectUris': ['https://app.example/../wrong']}).status_code == 400
    with app.app_context():
        demo = IdentityRepository(db.session).get_realm('demo')
        client_id = IdentityRepository(db.session).get_client(demo.id, 'demo-app').id
    assert client.get(ADMIN + '/master/clients/' + client_id, headers=admin_headers).status_code == 404
    assert client.put(ADMIN + '/demo/clients/' + client_id, headers=admin_headers,
                      json={'clientId': 'renamed'}).status_code == 400
    assert client.get(ADMIN + '/missing', headers=admin_headers).status_code == 404
    with app.app_context():
        assert db.session.scalar(select(Realm).where(Realm.name == 'bad/name')) is None
        assert db.session.scalar(select(Client).where(Client.client_id == 'bad')) is None


def test_client_secret_is_never_returned(app, client, admin_headers):
    path = ADMIN + '/demo/clients'
    secret = 'client-secret-value'
    created = client.post(path, headers=admin_headers, json={
        'clientId': 'backend', 'publicClient': False, 'secret': secret,
    })
    assert created.status_code == 201
    detail = client.get(created.headers['Location'], headers=admin_headers)
    assert detail.json['publicClient'] is False
    assert 'secret' not in detail.text
    with app.app_context():
        row = db.session.scalar(select(Client).where(Client.client_id == 'backend'))
        assert secret not in row.secret_hash


def test_bootstrap_creates_only_one_admin_identity(app):
    runner = app.test_cli_runner()
    first = runner.invoke(args=['admin-bootstrap', '--username', 'operator'],
                          input=f'{PASSWORD}\n{PASSWORD}\n')
    assert first.exit_code == 0
    second = runner.invoke(args=['admin-bootstrap', '--username', 'operator'],
                           input=f'{PASSWORD}\n{PASSWORD}\n')
    assert second.exit_code != 0
    with app.app_context():
        master = IdentityRepository(db.session).get_realm('master')
        assert master is not None
        assert len(IdentityRepository(db.session).list_users(master.id)) == 1
        assert len(IdentityRepository(db.session).list_clients(master.id)) == 1
        assert db.session.scalar(select(User).where(User.realm_id == master.id)).attributes == {
            'realmRoles': ['admin']}


def test_bootstrap_adds_admin_to_existing_master_realm(app, client):
    with app.app_context():
        value = validate_realm_import({'realm': 'master', 'displayName': 'Existing'}).value
        RealmImportService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET']).import_realm(value)
        db.session.commit()
    result = app.test_cli_runner().invoke(args=['admin-bootstrap', '--username', 'operator'],
                                          input=f'{PASSWORD}\n{PASSWORD}\n')
    assert result.exit_code == 0, result.output
    with app.app_context():
        master = IdentityRepository(db.session).get_realm('master')
        assert master.display_name == 'Existing'
    token = client.post('/realms/master/protocol/openid-connect/token', data={
        'grant_type': 'password', 'client_id': 'admin-cli',
        'username': 'operator', 'password': PASSWORD,
    })
    assert token.status_code == 200
    assert client.get(ADMIN, headers={'Authorization': 'Bearer ' + token.json['access_token']}).status_code == 200


def test_deleting_client_removes_its_sessions_and_preserves_other_clients(app, client, admin_headers):
    created = client.post(ADMIN + '/demo/clients', headers=admin_headers, json={
        'clientId': 'temporary', 'directAccessGrantsEnabled': True,
    })
    assert created.status_code == 201
    token = client.post('/realms/demo/protocol/openid-connect/token', data={
        'grant_type': 'password', 'client_id': 'temporary',
        'username': 'demo-user', 'password': 'DemoPassw0rd!',
    }).json
    assert token['access_token']
    removed = client.delete(created.headers['Location'], headers=admin_headers)
    assert removed.status_code == 204, removed.json
    assert client.get(created.headers['Location'], headers=admin_headers).status_code == 404
    assert client.post('/realms/demo/protocol/openid-connect/token', data={
        'grant_type': 'refresh_token', 'client_id': 'temporary',
        'refresh_token': token['refresh_token'],
    }).status_code == 401
    with app.app_context():
        assert db.session.scalar(select(RefreshToken).where(RefreshToken.client_id == created.json['id'])) is None
        assert db.session.scalar(select(UserSession).where(UserSession.client_id == created.json['id'])) is None
        demo = IdentityRepository(db.session).get_realm('demo')
        events = db.session.scalars(select(SecurityEvent).where(
            SecurityEvent.realm_id == demo.id,
            SecurityEvent.event_type == 'PASSWORD_GRANT')).all()
        assert len(events) == 1
        assert events[0].client_id is None and events[0].user_session_id is None
        assert IdentityRepository(db.session).get_client(demo.id, 'demo-app') is not None


def test_deleting_realm_removes_its_identity_and_sessions(app, client, admin_headers):
    created = client.post(ADMIN, headers=admin_headers, json={
        'realm': 'retired',
        'attributes': {'mini.keycloak.passwordGrantEnabled': 'true'},
        'clients': [{'clientId': 'app', 'directAccessGrantsEnabled': True}],
        'users': [{'username': 'alice', 'credentials': [
            {'type': 'password', 'value': 'AlicePassw0rd!'}]}],
    })
    assert created.status_code == 201
    tokens = client.post('/realms/retired/protocol/openid-connect/token', data={
        'grant_type': 'password', 'client_id': 'app',
        'username': 'alice', 'password': 'AlicePassw0rd!',
    }).json
    assert tokens['access_token']
    removed = client.delete(ADMIN + '/retired', headers=admin_headers)
    assert removed.status_code == 204, removed.json
    assert client.get(ADMIN + '/retired', headers=admin_headers).status_code == 404
    assert client.get('/realms/retired/.well-known/openid-configuration').status_code == 404
    with app.app_context():
        assert db.session.scalar(select(Client).where(Client.realm_id == created.json['id'])) is None
        assert db.session.scalar(select(User).where(User.realm_id == created.json['id'])) is None
        assert db.session.scalar(select(RefreshToken).where(RefreshToken.realm_id == created.json['id'])) is None
        assert IdentityRepository(db.session).get_realm('demo') is not None


def test_master_realm_cannot_be_deleted(client, admin_headers):
    assert client.delete(ADMIN + '/master', headers=admin_headers).status_code == 400


def test_client_create_only_import_rejects_existing_client_without_updating(app):
    with app.app_context():
        realm = IdentityRepository(db.session).get_realm('demo')
        existing = IdentityRepository(db.session).get_client(realm.id, 'demo-app')
        before = existing.name
        value = validate_realm_import({
            'realm': 'demo', 'clients': [{'clientId': 'DEMO-APP', 'name': 'changed'}],
        }, update=True).value
        with pytest.raises(ClientAlreadyExists):
            RealmImportService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET']).import_realm(
                value, update=True, create_only_clients=True)
        assert IdentityRepository(db.session).get_client(realm.id, 'demo-app').name == before


def test_client_create_reports_conflict_when_competing_insert_becomes_visible(
        app, client, admin_headers, monkeypatch):
    original = RealmImportService.import_realm

    def competing_insert(service, value, **options):
        if options.get('create_only_clients'):
            realm = IdentityRepository(db.session).get_realm('demo')
            IdentityRepository(db.session).create_client(
                realm.id, 'racing', redirect_uris=[])
            db.session.commit()
            raise RealmImportError('Realm import failed')
        return original(service, value, **options)

    monkeypatch.setattr(RealmImportService, 'import_realm', competing_insert)
    response = client.post(ADMIN + '/demo/clients', headers=admin_headers,
                           json={'clientId': 'racing'})
    assert response.status_code == 409
    with app.app_context():
        realm = IdentityRepository(db.session).get_realm('demo')
        assert IdentityRepository(db.session).get_client(realm.id, 'racing') is not None
