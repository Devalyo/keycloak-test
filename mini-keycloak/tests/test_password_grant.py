import jwt
import pytest
from sqlalchemy import select
from werkzeug.datastructures import MultiDict

from mini_keycloak.extensions import db
from mini_keycloak.models import Client, Realm, RealmKey, RefreshToken, User, UserSession
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.bootstrap import ensure_demo_realm
from tests.test_client_authentication import SECRET, TOKEN, basic, confidential
from tests.test_jwt_tokens import service


def password_grant(client, **changes):
    data = dict(grant_type='password', client_id='demo-app', username='demo-user',
                password='DemoPassw0rd!')
    data.update(changes)
    return client.post(TOKEN, data={key: value for key, value in data.items() if value is not None})


def test_public_password_form_creates_session_and_signed_tokens(app, client):
    response = password_grant(client)
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    with app.app_context():
        realm = db.session.scalar(select(Realm))
        session = db.session.scalar(select(UserSession))
        assert session is not None
        for field, typ in [('access_token', 'Bearer'), ('id_token', 'ID'), ('refresh_token', 'Refresh')]:
            claims = service(app).verify(response.json[field], realm=realm, audience='demo-app', token_type=typ)
            assert claims['sid'] == response.json['session_state'] == session.sid
            assert claims['scope'] == 'openid profile email'
            assert 'nonce' not in claims
        assert db.session.scalar(select(RefreshToken)).user_session_id == session.id


@pytest.mark.parametrize('method', ['post', 'basic'])
def test_password_grant_authenticates_confidential_clients(app, client, method):
    confidential(app)
    if method == 'post':
        response = password_grant(client, client_secret=SECRET)
    else:
        response = client.post(TOKEN, headers=basic(), data=dict(
            grant_type='password', username='demo-user', password='DemoPassw0rd!'))
    assert response.status_code == 200
    assert jwt.get_unverified_header(response.json['access_token'])['alg'] == 'RS256'


@pytest.mark.parametrize('mutation,status,error', [
    ('realm_policy', 400, 'unauthorized_client'), ('client_policy', 400, 'unauthorized_client'),
    ('realm', 404, 'invalid_request'), ('client', 401, 'invalid_client'),
    ('user', 400, 'invalid_grant'), ('wrong_password', 400, 'invalid_grant'),
    ('unknown_user', 400, 'invalid_grant'),
])
def test_password_grant_rejects_policy_and_credentials_without_session(app, client, mutation, status, error):
    changes = {}
    with app.app_context():
        if mutation in {'realm', 'client', 'user'}:
            db.session.scalar(select({'realm': Realm, 'client': Client, 'user': User}[mutation])).enabled = False
        elif mutation == 'realm_policy':
            db.session.scalar(select(Realm)).password_grant_enabled = False
        elif mutation == 'client_policy':
            db.session.scalar(select(Client)).direct_access_grants_enabled = False
        elif mutation == 'wrong_password':
            changes['password'] = 'wrong'
        else:
            changes['username'] = 'unknown'
        db.session.commit()
    response = password_grant(client, **changes)
    assert (response.status_code, response.json) == (status, {'error': error})
    with app.app_context():
        assert db.session.scalar(select(UserSession)) is None
        assert db.session.scalar(select(RefreshToken)) is None


@pytest.mark.parametrize('scope', ['openid admin', 'offline_access', 'unknown'])
def test_password_grant_rejects_ungranted_scopes(client, scope):
    response = password_grant(client, scope=scope)
    assert (response.status_code, response.json) == (400, {'error': 'invalid_scope'})


def test_password_scope_limits_claims_and_id_token(app, client):
    response = password_grant(client, scope='profile')
    assert response.status_code == 200
    assert response.json['scope'] == 'profile'
    assert 'id_token' not in response.json
    claims = jwt.decode(response.json['access_token'], options={'verify_signature': False})
    assert claims['preferred_username'] == 'demo-user'
    assert 'email' not in claims


@pytest.mark.parametrize('parameter', ['username', 'password', 'scope'])
def test_password_grant_rejects_duplicated_parameters(client, parameter):
    data = MultiDict(dict(grant_type='password', client_id='demo-app', username='demo-user',
                          password='DemoPassw0rd!', scope='openid'))
    data.add(parameter, data[parameter])
    assert client.post(TOKEN, data=data).json == {'error': 'invalid_request'}


def test_password_grant_does_not_find_users_in_other_realms(app, client):
    with app.app_context():
        repository = IdentityRepository(db.session)
        other = repository.create_realm('other')
        other.password_grant_enabled = True
        repository.create_client(other.id, 'demo-app', redirect_uris=[], direct_access_grants_enabled=True)
        db.session.commit()
    response = client.post(TOKEN.replace('/demo/', '/other/'), data=dict(
        grant_type='password', client_id='demo-app', username='demo-user', password='DemoPassw0rd!'))
    assert (response.status_code, response.json) == (400, {'error': 'invalid_grant'})


def test_password_signing_failure_rolls_back_new_session(app, client):
    with app.app_context():
        db.session.scalar(select(RealmKey)).active = False
        db.session.commit()
    response = password_grant(client)
    assert response.status_code == 503
    with app.app_context():
        assert db.session.scalar(select(UserSession)) is None
        assert db.session.scalar(select(RefreshToken)) is None


def test_realm_direct_grants_default_closed_and_bootstrap_enables_only_poc(app):
    with app.app_context():
        other = IdentityRepository(db.session).create_realm('other')
        assert other.password_grant_enabled is False
        realm = db.session.scalar(select(Realm).where(Realm.name == 'demo'))
        realm.password_grant_enabled = False
        db.session.commit()  # Bootstrap uses the importer's clean-session boundary.
        ensure_demo_realm(db.session)
        assert realm.password_grant_enabled is True
        assert other.password_grant_enabled is False
        client = db.session.scalar(select(Client))
        assert client.public_client and client.direct_access_grants_enabled
