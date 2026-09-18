from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import hashlib
from threading import Barrier

import jwt
import pytest
from sqlalchemy import select
from werkzeug.datastructures import MultiDict

from mini_keycloak.extensions import db
from mini_keycloak.models import Client, Realm, RealmKey, RefreshToken, User, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.security.key_encryption import decrypt_private_pem
from tests.test_client_authentication import SECRET, TOKEN, basic, confidential
from tests.test_jwt_tokens import issued, service


def refresh(client, raw, **changes):
    data = dict(grant_type='refresh_token', client_id='demo-app', refresh_token=raw)
    data.update(changes)
    return client.post(TOKEN, data={key: value for key, value in data.items() if value is not None})


def test_rotation_preserves_session_and_family_and_advances_generation(app, client):
    original = issued(client)
    response = refresh(client, original['refresh_token'])
    assert response.status_code == 200
    tokens = response.json
    assert set(tokens) == set(original)
    assert tokens['session_state'] == original['session_state']
    assert response.headers['Cache-Control'] == 'no-store'
    with app.app_context():
        realm = db.session.scalar(select(Realm))
        rows = db.session.scalars(select(RefreshToken).order_by(RefreshToken.generation)).all()
        assert len(rows) == 2
        assert [row.generation for row in rows] == [0, 1]
        assert rows[0].family_id == rows[1].family_id
        assert rows[0].used_at is not None and rows[1].used_at is None
        assert rows[0].replaced_by_id == rows[1].id
        assert rows[0].token_hash == hashlib.sha256(original['refresh_token'].encode()).hexdigest()
        assert rows[1].token_hash == hashlib.sha256(tokens['refresh_token'].encode()).hexdigest()
        for field, typ in [('access_token', 'Bearer'), ('id_token', 'ID'), ('refresh_token', 'Refresh')]:
            claims = service(app).verify(tokens[field], realm=realm, audience='demo-app', token_type=typ)
            old = jwt.decode(original[field], options={'verify_signature': False})
            assert claims['auth_time'] == old['auth_time']
            assert claims['sid'] == old['sid'] and claims['sub'] == old['sub']
            assert claims['jti'] != old['jti']
            if typ == 'Refresh':
                assert claims['generation'] == 1
        assert rows[1].scope == 'openid profile email'
    assert refresh(client, tokens['refresh_token']).status_code == 200


def test_reuse_revokes_entire_family_and_session_but_not_other_sessions(app, client):
    original = issued(client)
    independent = issued(app.test_client())
    second = refresh(client, original['refresh_token']).json
    third_response = refresh(client, second.get('refresh_token', ''))
    assert third_response.status_code == 200
    third = third_response.json
    response = refresh(client, original['refresh_token'])
    assert (response.status_code, response.json) == (400, {'error': 'invalid_grant'})
    with app.app_context():
        session = db.session.scalar(select(UserSession).where(UserSession.sid == original['session_state']))
        rows = db.session.scalars(select(RefreshToken).where(RefreshToken.user_session_id == session.id)).all()
        assert len(rows) == 3 and all(row.revoked_at is not None for row in rows)
        assert session.revoked_at is not None
        from mini_keycloak.oidc.errors import InvalidToken
        with pytest.raises(InvalidToken):
            service(app).verify(third['access_token'], realm=db.session.scalar(select(Realm)),
                                audience='demo-app', token_type='Bearer')
    assert refresh(client, third['refresh_token']).json == {'error': 'invalid_grant'}
    assert refresh(client, independent['refresh_token']).status_code == 200


@pytest.mark.parametrize('mutation', ['signature', 'issuer', 'audience', 'type', 'subject',
                                      'sid', 'scope', 'generation', 'jti', 'expired', 'missing_exp'])
def test_refresh_rejects_invalid_signatures_claims_and_untracked_signed_tokens(app, client, mutation):
    original = issued(client)
    with app.app_context():
        key = db.session.scalar(select(RealmKey))
        claims = jwt.decode(original['refresh_token'], options={'verify_signature': False})
        signing_key = decrypt_private_pem(key.encrypted_private_pem, app.config['OIDC_KEY_ENCRYPTION_SECRET'])
        if mutation == 'signature':
            from cryptography.hazmat.primitives.asymmetric import rsa
            signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif mutation == 'expired':
            claims['exp'] = 1
        elif mutation == 'missing_exp':
            del claims['exp']
        elif mutation == 'generation':
            claims['generation'] = 99
        else:
            claims[{'issuer': 'iss', 'audience': 'aud', 'type': 'typ', 'subject': 'sub'}.get(mutation, mutation)] = 'other'
        raw = jwt.encode(claims, signing_key, algorithm='RS256', headers={'kid': key.kid})
    response = refresh(client, raw)
    assert (response.status_code, response.json) == (400, {'error': 'invalid_grant'})
    assert refresh(client, original['refresh_token']).status_code == 200


@pytest.mark.parametrize('mutation', ['realm', 'client', 'user', 'session_revoked', 'idle', 'maximum',
                                      'row_revoked', 'row_expired', 'row_hash', 'row_scope', 'row_generation'])
def test_refresh_enforces_live_policy_and_persisted_binding(app, client, mutation):
    original = issued(client)
    with app.app_context():
        if mutation in {'realm', 'client', 'user'}:
            db.session.scalar(select({'realm': Realm, 'client': Client, 'user': User}[mutation])).enabled = False
        elif mutation.startswith('row_'):
            row = db.session.scalar(select(RefreshToken))
            field, value = {
                'row_revoked': ('revoked_at', utc_now()),
                'row_expired': ('expires_at', utc_now() - timedelta(seconds=1)),
                'row_hash': ('token_hash', '0' * 64), 'row_scope': ('scope', 'openid'),
                'row_generation': ('generation', 99),
            }[mutation]
            setattr(row, field, value)
        else:
            session = db.session.scalar(select(UserSession))
            setattr(session, {'session_revoked': 'revoked_at', 'idle': 'idle_expires_at',
                              'maximum': 'max_expires_at'}[mutation], utc_now())
        db.session.commit()
    response = refresh(client, original['refresh_token'])
    expected = {'realm': (404, 'invalid_request'), 'client': (401, 'invalid_client')}.get(
        mutation, (400, 'invalid_grant'))
    assert (response.status_code, response.json) == (expected[0], {'error': expected[1]})
    with app.app_context():
        assert len(db.session.scalars(select(RefreshToken)).all()) == 1
        assert db.session.scalar(select(RefreshToken)).used_at is None


def test_refresh_cannot_cross_client_or_realm(app, client):
    original = issued(client)
    with app.app_context():
        identities = IdentityRepository(db.session)
        realm = identities.get_realm('demo')
        identities.create_client(realm.id, 'other', redirect_uris=[])
        other = identities.create_realm('other')
        identities.create_client(other.id, 'demo-app', redirect_uris=[])
        db.session.commit()
    assert refresh(client, original['refresh_token'], client_id='other').json == {'error': 'invalid_grant'}
    assert client.post(TOKEN.replace('/demo/', '/other/'), data=dict(
        grant_type='refresh_token', client_id='demo-app', refresh_token=original['refresh_token'])).json == {'error': 'invalid_grant'}
    assert refresh(client, original['refresh_token']).status_code == 200


@pytest.mark.parametrize('method', ['post', 'basic'])
def test_refresh_requires_confidential_client_authentication(app, client, method):
    original = issued(client)
    confidential(app)
    assert refresh(client, original['refresh_token']).json == {'error': 'invalid_client'}
    if method == 'post':
        response = refresh(client, original['refresh_token'], client_secret=SECRET)
    else:
        response = client.post(TOKEN, headers=basic(), data=dict(
            grant_type='refresh_token', refresh_token=original['refresh_token']))
    assert response.status_code == 200


def test_refresh_signing_failure_rolls_back_rotation(app, client):
    original = issued(client)
    with app.app_context():
        db.session.scalar(select(RealmKey)).active = False
        db.session.commit()
    assert refresh(client, original['refresh_token']).status_code == 503
    with app.app_context():
        rows = db.session.scalars(select(RefreshToken)).all()
        assert len(rows) == 1 and rows[0].used_at is None and rows[0].replaced_by_id is None
        db.session.scalar(select(RealmKey)).active = True
        db.session.commit()
    assert refresh(client, original['refresh_token']).status_code == 200


@pytest.mark.parametrize('raw', [None, ''])
def test_refresh_requires_token_parameter(client, raw):
    assert refresh(client, raw).json == {'error': 'invalid_request'}


def test_duplicate_refresh_parameter_is_rejected(client):
    data = MultiDict([('grant_type', 'refresh_token'), ('client_id', 'demo-app'),
                      ('refresh_token', 'one'), ('refresh_token', 'two')])
    assert client.post(TOKEN, data=data).json == {'error': 'invalid_request'}


def test_refresh_scope_can_narrow_but_never_expand(client):
    original = issued(client)
    rejected = refresh(client, original['refresh_token'], scope='openid profile email admin')
    assert (rejected.status_code, rejected.json) == (400, {'error': 'invalid_scope'})
    response = refresh(client, original['refresh_token'], scope='profile')
    assert response.status_code == 200
    assert response.json['scope'] == 'profile' and 'id_token' not in response.json
    claims = jwt.decode(response.json['access_token'], options={'verify_signature': False})
    assert claims['preferred_username'] == 'demo-user' and 'email' not in claims
    assert refresh(client, response.json['refresh_token'], scope='openid profile').json == {'error': 'invalid_scope'}
    assert refresh(client, response.json['refresh_token']).json['scope'] == 'profile'


def test_refresh_extends_idle_session_without_extending_maximum(app, client):
    original = issued(client)
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        before_idle = utc_now() + timedelta(seconds=20)
        maximum = utc_now() + timedelta(seconds=70)
        session.idle_expires_at, session.max_expires_at = before_idle, maximum
        db.session.commit()
    response = refresh(client, original['refresh_token'])
    assert response.status_code == 200
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        assert before_idle < session.idle_expires_at == maximum
        assert session.max_expires_at == maximum
        assert 0 < response.json['refresh_expires_in'] <= 70


def test_refresh_rechecks_token_expiry_after_waiting_for_session_lock(app, client, monkeypatch):
    with app.app_context():
        db.session.scalar(select(Realm)).refresh_token_lifetime_seconds = 10
        db.session.commit()
    original = issued(client)
    now = utc_now()
    moments = [now, now + timedelta(seconds=11)]
    monkeypatch.setattr('mini_keycloak.services.tokens.utc_now',
                        lambda: moments.pop(0) if len(moments) > 1 else moments[0])
    response = refresh(client, original['refresh_token'])
    assert (response.status_code, response.json) == (400, {'error': 'invalid_grant'})
    with app.app_context():
        assert db.session.scalar(select(RefreshToken)).used_at is None


def test_concurrent_refresh_has_one_winner_and_commits_reuse_revocation(app, client, monkeypatch):
    from mini_keycloak.repositories.protocol import RefreshTokenRepository
    original = issued(client)
    barrier = Barrier(2, timeout=10)
    existing = RefreshTokenRepository.lock_session

    def synchronized(service, *args, **kwargs):
        barrier.wait()
        return existing(service, *args, **kwargs)

    monkeypatch.setattr(RefreshTokenRepository, 'lock_session', synchronized)

    def request_tokens(_):
        with app.test_client() as worker:
            response = refresh(worker, original['refresh_token'])
            return response.status_code, response.json

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(request_tokens, range(2)))
    assert sorted(status for status, _ in responses) == [200, 400]
    assert [body for status, body in responses if status == 400] == [{'error': 'invalid_grant'}]
    with app.app_context():
        rows = db.session.scalars(select(RefreshToken)).all()
        assert len(rows) == 2 and all(row.revoked_at is not None for row in rows)
        assert db.session.scalar(select(UserSession)).revoked_at is not None
