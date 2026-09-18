from datetime import timedelta

import jwt
import pytest
from sqlalchemy import select
from werkzeug.datastructures import MultiDict

from mini_keycloak.extensions import db
from mini_keycloak.models import Client, Realm, RealmKey, User, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.security.key_encryption import decrypt_private_pem
from tests.test_jwt_tokens import issued


USERINFO = '/realms/demo/protocol/openid-connect/userinfo'


def bearer(raw):
    return {'Authorization': 'Bearer ' + raw}


def signed_variant(app, raw, **changes):
    with app.app_context():
        key = db.session.scalar(select(RealmKey))
        claims = jwt.decode(raw, options={'verify_signature': False}) | changes
        private = decrypt_private_pem(key.encrypted_private_pem, app.config['OIDC_KEY_ENCRYPTION_SECRET'])
        return jwt.encode(claims, private, algorithm='RS256', headers={'kid': key.kid})


@pytest.mark.parametrize('method,source', [('get', 'header'), ('post', 'header'), ('post', 'form')])
@pytest.mark.parametrize('scope,fields', [
    ('openid', {'sub'}), ('openid profile', {'sub', 'preferred_username'}),
    ('openid email', {'sub', 'email', 'email_verified'}),
    ('openid profile email', {'sub', 'preferred_username', 'email', 'email_verified'}),
])
def test_userinfo_accepts_one_bearer_source_and_limits_claims(app, client, method, source, scope, fields):
    tokens = issued(client, scope=scope)
    options = {'headers': bearer(tokens['access_token'])} if source == 'header' else {
        'data': {'access_token': tokens['access_token']}}
    response = getattr(client, method)(USERINFO, **options)
    assert response.status_code == 200
    assert set(response.json) == fields
    with app.app_context():
        user = db.session.scalar(select(User))
        assert response.json['sub'] == user.id
        if 'preferred_username' in fields:
            assert response.json['preferred_username'] == 'demo-user'
        if 'email' in fields:
            assert response.json['email'] == user.email
            assert response.json['email_verified'] is False
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['Pragma'] == 'no-cache'


@pytest.mark.parametrize('source', ['missing', 'query', 'query_header', 'form_header', 'repeated', 'basic', 'empty', 'spaces'])
def test_userinfo_rejects_missing_ambiguous_or_malformed_bearer(client, source):
    raw = issued(client)['access_token']
    options = {
        'missing': {}, 'query': {'query_string': {'access_token': raw}},
        'query_header': {'headers': bearer(raw), 'query_string': {'access_token': raw}},
        'form_header': {'headers': bearer(raw), 'data': {'access_token': raw}},
        'repeated': {'data': MultiDict([('access_token', raw), ('access_token', raw)])},
        'basic': {'headers': {'Authorization': 'Basic ' + raw}},
        'empty': {'headers': {'Authorization': 'Bearer '}},
        'spaces': {'headers': {'Authorization': 'Bearer ' + raw + ' extra'}},
    }[source]
    response = client.post(USERINFO, **options)
    assert response.status_code in {400, 401}
    assert response.headers['WWW-Authenticate'].startswith('Bearer')
    assert 'sub' not in response.json


@pytest.mark.parametrize('changes', [
    {'iss': 'https://other.test'}, {'aud': 'unknown'}, {'azp': 'unknown'},
    {'typ': 'ID'}, {'sub': 'unknown'}, {'sid': 'unknown'}, {'auth_time': 1},
    {'exp': 1}, {'aud': ['demo-app', 'other']},
])
def test_userinfo_checks_signed_claims_and_live_binding(app, client, changes):
    raw = signed_variant(app, issued(client)['access_token'], **changes)
    response = client.get(USERINFO, headers=bearer(raw))
    assert (response.status_code, response.json) == (401, {'error': 'invalid_token'})


@pytest.mark.parametrize('kind', ['id_token', 'refresh_token', 'malformed', 'unsigned', 'hs256'])
def test_userinfo_rejects_other_token_types_and_algorithms(client, kind):
    tokens = issued(client)
    raw = tokens.get(kind, 'not-a-token')
    if kind in {'unsigned', 'hs256'}:
        claims = jwt.decode(tokens['access_token'], options={'verify_signature': False})
        raw = jwt.encode(claims, '' if kind == 'unsigned' else 'x' * 32,
                         algorithm='none' if kind == 'unsigned' else 'HS256')
    response = client.get(USERINFO, headers=bearer(raw))
    assert (response.status_code, response.json) == (401, {'error': 'invalid_token'})


@pytest.mark.parametrize('mutation', ['realm', 'client', 'user', 'revoked', 'idle', 'maximum'])
def test_userinfo_rejects_ineligible_backing_state(app, client, mutation):
    raw = issued(client)['access_token']
    with app.app_context():
        if mutation in {'realm', 'client', 'user'}:
            db.session.scalar(select({'realm': Realm, 'client': Client, 'user': User}[mutation])).enabled = False
        else:
            session = db.session.scalar(select(UserSession))
            setattr(session, {'revoked': 'revoked_at', 'idle': 'idle_expires_at',
                              'maximum': 'max_expires_at'}[mutation], utc_now() - timedelta(seconds=1))
        db.session.commit()
    response = client.get(USERINFO, headers=bearer(raw))
    assert response.status_code == (404 if mutation == 'realm' else 401)


def test_userinfo_does_not_accept_tokens_in_another_realm(app, client):
    from mini_keycloak.repositories.identity import IdentityRepository
    raw = issued(client)['access_token']
    with app.app_context():
        other = IdentityRepository(db.session).create_realm('other')
        IdentityRepository(db.session).create_client(other.id, 'demo-app', redirect_uris=[])
        db.session.commit()
    response = client.get(USERINFO.replace('/demo/', '/other/'), headers=bearer(raw))
    assert (response.status_code, response.json) == (401, {'error': 'invalid_token'})
