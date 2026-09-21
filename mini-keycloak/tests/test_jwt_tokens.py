from datetime import timedelta

import jwt
import pytest
from sqlalchemy import select

from mini_keycloak.extensions import db
from mini_keycloak.models import Client, Realm, RealmKey, RefreshToken, User, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.security.key_encryption import decrypt_private_pem
from tests.test_authorization_code import issue, returned_code
from tests.test_token_endpoint import exchange


def service(app):
    from mini_keycloak.services.tokens import TokenService
    return TokenService(db.session, external_url=app.config['EXTERNAL_URL'],
                        master_secret=app.config['OIDC_KEY_ENCRYPTION_SECRET'],
                        access_seconds=300, refresh_seconds=1800)


def issued(client, **params):
    response = exchange(client, returned_code(issue(client, **params)))
    assert response.status_code == 200
    return response.json


def test_rs256_tokens_verify_with_published_jwks_and_include_bound_claims(app, client):
    tokens = issued(client)
    issuer = client.get('/realms/demo/.well-known/openid-configuration').json['issuer']
    jwk = client.get('/realms/demo/protocol/openid-connect/certs').json['keys'][0]
    public_key = jwt.PyJWK.from_dict(jwk).key
    with app.app_context():
        user = db.session.scalar(select(User))
        session = db.session.scalar(select(UserSession))
        jtis = set()
        for kind, typ in [('access_token', 'Bearer'), ('id_token', 'ID'), ('refresh_token', 'Refresh')]:
            token = tokens[kind]
            assert jwt.get_unverified_header(token) == {'alg': 'RS256', 'kid': jwk['kid'], 'typ': 'JWT'}
            claims = jwt.decode(token, public_key, algorithms=['RS256'], issuer=issuer, audience='demo-app')
            assert claims['iss'] == issuer
            assert claims['sub'] == user.id
            assert claims['aud'] == claims['azp'] == 'demo-app'
            assert claims['typ'] == typ
            assert claims['sid'] == session.sid
            assert claims['auth_time'] == int(session.auth_time.timestamp())
            assert claims['iat'] <= int(utc_now().timestamp()) < claims['exp']
            assert claims['scope'] == 'openid profile email'
            assert claims['preferred_username'] == 'demo-user'
            assert claims['email'] == user.email
            assert claims['email_verified'] is False
            jtis.add(claims['jti'])
        assert len(jtis) == 3
        assert jwt.decode(tokens['id_token'], public_key, algorithms=['RS256'],
                          audience='demo-app')['nonce'] == 'nonce-value'


def test_claims_are_scope_limited_and_absent_nonce_is_omitted(client):
    tokens = issued(client, scope='openid', nonce=None)
    for name in ['access_token', 'id_token', 'refresh_token']:
        claims = jwt.decode(tokens[name], options={'verify_signature': False})
        assert 'preferred_username' not in claims
        assert 'email' not in claims and 'email_verified' not in claims
        assert 'nonce' not in claims


def test_realm_issuer_override_and_lifetimes_apply_to_tokens_and_discovery(app, client):
    with app.app_context():
        realm = db.session.scalar(select(Realm))
        realm.issuer_override = 'https://login.example.test/custom'
        realm.access_token_lifetime_seconds = 17
        realm.refresh_token_lifetime_seconds = 29
        db.session.commit()
    tokens = issued(client)
    assert tokens['expires_in'] == 17 and tokens['refresh_expires_in'] == 29
    assert client.get('/realms/demo/.well-known/openid-configuration').json['issuer'] == 'https://login.example.test/custom'
    with app.app_context():
        claims = service(app).verify(tokens['access_token'], realm=db.session.scalar(select(Realm)),
                                     audience='demo-app', token_type='Bearer')
        assert claims['iss'] == 'https://login.example.test/custom'


@pytest.mark.parametrize('mutation', ['algorithm', 'issuer', 'audience', 'kid', 'signature',
                                      'expired', 'type', 'subject', 'azp', 'sid', 'missing_exp'])
def test_verification_rejects_invalid_token_claims_and_signatures(app, client, mutation):
    tokens = issued(client)
    with app.app_context():
        from mini_keycloak.oidc.errors import InvalidToken
        key = db.session.scalar(select(RealmKey))
        claims = jwt.decode(tokens['access_token'], options={'verify_signature': False})
        headers = {'kid': key.kid}
        signing_key = decrypt_private_pem(key.encrypted_private_pem, app.config['OIDC_KEY_ENCRYPTION_SECRET'])
        algorithm = 'RS256'
        if mutation == 'algorithm':
            algorithm, signing_key = 'HS256', 'different-secret-with-at-least-32-bytes'
        elif mutation == 'kid':
            headers['kid'] = 'unknown'
        elif mutation == 'signature':
            from cryptography.hazmat.primitives.asymmetric import rsa
            signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif mutation == 'expired':
            claims['exp'] = 1
        elif mutation == 'missing_exp':
            del claims['exp']
        else:
            claim = {'issuer': 'iss', 'audience': 'aud', 'type': 'typ', 'subject': 'sub'}.get(mutation, mutation)
            claims[claim] = 'other'
        forged = jwt.encode(claims, signing_key, algorithm=algorithm, headers=headers)
        with pytest.raises(InvalidToken):
            service(app).verify(forged, realm=db.session.scalar(select(Realm)),
                                audience='demo-app', token_type='Bearer')


@pytest.mark.parametrize('mutation', ['realm', 'client', 'user', 'revoked', 'idle', 'maximum'])
def test_verification_checks_live_backing_state(app, client, mutation):
    tokens = issued(client)
    with app.app_context():
        from mini_keycloak.oidc.errors import InvalidToken
        if mutation in {'realm', 'client', 'user'}:
            db.session.scalar(select({'realm': Realm, 'client': Client, 'user': User}[mutation])).enabled = False
        else:
            session = db.session.scalar(select(UserSession))
            field = {'revoked': 'revoked_at', 'idle': 'idle_expires_at', 'maximum': 'max_expires_at'}[mutation]
            setattr(session, field, utc_now() - timedelta(seconds=1))
        db.session.commit()
        with pytest.raises(InvalidToken):
            service(app).verify(tokens['access_token'], realm=db.session.scalar(select(Realm)),
                                audience='demo-app', token_type='Bearer')


def test_verification_is_explicit_about_audience_type_and_realm(app, client):
    tokens = issued(client)
    with app.app_context():
        from mini_keycloak.oidc.errors import InvalidToken
        from mini_keycloak.repositories.identity import IdentityRepository
        realm = db.session.scalar(select(Realm))
        other = IdentityRepository(db.session).create_realm('other')
        for expected_realm, audience, typ in [(realm, 'other', 'Bearer'), (realm, 'demo-app', 'ID'), (other, 'demo-app', 'Bearer')]:
            with pytest.raises(InvalidToken):
                service(app).verify(tokens['access_token'], realm=expected_realm, audience=audience, token_type=typ)


def test_retained_key_verifies_old_tokens_after_rotation(app, client):
    tokens = issued(client)
    with app.app_context():
        from mini_keycloak.services.keys import RealmKeyService
        realm = db.session.scalar(select(Realm))
        old_key = db.session.scalar(select(RealmKey))
        old_kid = old_key.kid
        new_key = RealmKeyService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET']).rotate_active_key(realm.id)
        assert new_key.kid != old_key.kid
        db.session.commit()
        assert service(app).verify(tokens['access_token'], realm=realm, audience='demo-app', token_type='Bearer')
    new_tokens = issued(app.test_client())
    jwks = client.get('/realms/demo/protocol/openid-connect/certs').json['keys']
    assert {key['kid'] for key in jwks} == {old_kid, new_key.kid}
    assert all(set(key) == {'kid', 'kty', 'alg', 'use', 'n', 'e'} for key in jwks)
    for token_set, expected_kid in [(tokens, old_kid), (new_tokens, new_key.kid)]:
        public = jwt.PyJWK.from_dict(next(key for key in jwks if key['kid'] == expected_kid)).key
        for kind in ['access_token', 'id_token', 'refresh_token']:
            assert jwt.get_unverified_header(token_set[kind])['kid'] == expected_kid
            assert jwt.decode(token_set[kind], public, algorithms=['RS256'], audience='demo-app')


def test_refresh_token_requires_persisted_active_identifier(app, client):
    tokens = issued(client)
    with app.app_context():
        from mini_keycloak.oidc.errors import InvalidToken
        realm = db.session.scalar(select(Realm))
        assert service(app).verify(tokens['refresh_token'], realm=realm, audience='demo-app', token_type='Refresh')
        db.session.scalar(select(RefreshToken)).revoked_at = utc_now()
        db.session.commit()
        with pytest.raises(InvalidToken):
            service(app).verify(tokens['refresh_token'], realm=realm, audience='demo-app', token_type='Refresh')
