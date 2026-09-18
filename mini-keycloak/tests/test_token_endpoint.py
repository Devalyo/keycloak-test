import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import jwt
import pytest
from sqlalchemy import select
from werkzeug.datastructures import MultiDict

from mini_keycloak.extensions import db
from mini_keycloak.models import AuthorizationCode, Client, Realm, RealmKey, RefreshToken, User, UserSession
from mini_keycloak.models.identity import utc_now
from tests.test_authorization_code import PARAMS, VERIFIER, issue, returned_code
from tests.test_client_authentication import SECRET, TOKEN, basic, confidential


def exchange(client, raw, **changes):
    data = dict(grant_type='authorization_code', client_id='demo-app', code=raw,
                redirect_uri=PARAMS['redirect_uri'], code_verifier=VERIFIER)
    data.update(changes)
    return client.post(TOKEN, data={key: value for key, value in data.items() if value is not None})


def test_code_exchange_returns_signed_tokens_and_persists_refresh_family(app, client):
    raw = returned_code(issue(client))
    response = exchange(client, raw)
    assert response.status_code == 200
    tokens = response.json
    assert set(tokens) == {'access_token', 'id_token', 'refresh_token', 'expires_in',
                           'refresh_expires_in', 'token_type', 'not-before-policy',
                           'session_state', 'scope'}
    assert tokens['token_type'] == 'Bearer'
    assert tokens['not-before-policy'] == 0
    assert tokens['scope'] == 'openid profile email'
    assert 0 < tokens['expires_in'] <= 300
    assert 0 < tokens['refresh_expires_in'] <= 1800
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['Pragma'] == 'no-cache'
    with app.app_context():
        code = db.session.scalar(select(AuthorizationCode))
        session = db.session.scalar(select(UserSession))
        refresh = db.session.scalar(select(RefreshToken))
        claims = jwt.decode(tokens['refresh_token'], options={'verify_signature': False})
        assert refresh.token_hash == hashlib.sha256(tokens['refresh_token'].encode()).hexdigest()
        assert tokens['refresh_token'] not in vars(refresh).values()
        assert refresh.family_id and refresh.generation == 0
        assert refresh.used_at is None and refresh.revoked_at is None
        assert (refresh.realm_id, refresh.client_id, refresh.user_id, refresh.user_session_id) == (
            code.realm_id, code.client_id, code.user_id, session.id)
        assert refresh.scope == code.scope
        assert int(refresh.expires_at.timestamp()) == claims['exp']
        assert tokens['session_state'] == session.sid
        assert code.consumed_at is not None
    assert exchange(client, raw).json == {'error': 'invalid_grant'}


@pytest.mark.parametrize('method', ['basic', 'post'])
def test_confidential_code_exchange(app, client, method):
    confidential(app)
    raw = returned_code(issue(client))
    if method == 'post':
        response = exchange(client, raw, client_secret=SECRET)
    else:
        response = client.post(TOKEN, headers=basic(), data=dict(
            grant_type='authorization_code', code=raw,
            redirect_uri=PARAMS['redirect_uri'], code_verifier=VERIFIER))
    assert response.status_code == 200
    assert 'id_token' in response.json


@pytest.mark.parametrize('changes,error', [
    ({'code': 'unknown'}, 'invalid_grant'),
    ({'code': None}, 'invalid_request'),
    ({'code': ''}, 'invalid_request'),
    ({'redirect_uri': None}, 'invalid_request'),
    ({'redirect_uri': PARAMS['redirect_uri'] + '/'}, 'invalid_grant'),
    ({'code_verifier': None}, 'invalid_grant'),
    ({'code_verifier': ''}, 'invalid_grant'),
    ({'code_verifier': 'x' * 43}, 'invalid_grant'),
    ({'grant_type': None}, 'invalid_request'),
    ({'grant_type': 'refresh_token'}, 'invalid_request'),
])
def test_rejected_requests_leave_code_available(app, client, changes, error):
    raw = returned_code(issue(client))
    response = exchange(client, raw, **changes)
    assert response.status_code == 400
    assert response.json == {'error': error}
    with app.app_context():
        assert db.session.scalar(select(AuthorizationCode)).consumed_at is None
        assert db.session.scalar(select(RefreshToken)) is None
    assert exchange(client, raw).status_code == 200


@pytest.mark.parametrize('parameter', ['grant_type', 'code', 'redirect_uri', 'code_verifier'])
def test_duplicate_grant_parameters_are_rejected(client, parameter):
    raw = returned_code(issue(client))
    data = MultiDict(dict(grant_type='authorization_code', client_id='demo-app', code=raw,
                          redirect_uri=PARAMS['redirect_uri'], code_verifier=VERIFIER))
    data.add(parameter, data[parameter])
    response = client.post(TOKEN, data=data)
    assert response.status_code == 400
    assert response.json == {'error': 'invalid_request'}
    assert exchange(client, raw).status_code == 200


@pytest.mark.parametrize('verifier', ['', VERIFIER])
def test_optional_pkce_distinguishes_empty_and_absent_verifier(client, verifier):
    raw = returned_code(issue(client, code_challenge=None, code_challenge_method=None))
    assert exchange(client, raw, code_verifier=verifier).json == {'error': 'invalid_grant'}
    assert exchange(client, raw, code_verifier=None).status_code == 200


@pytest.mark.parametrize('mutation', ['expired', 'revoked', 'idle', 'maximum', 'user', 'standard_flow'])
def test_code_exchange_rejects_ineligible_backing_state(app, client, mutation):
    raw = returned_code(issue(client))
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        if mutation == 'expired':
            db.session.scalar(select(AuthorizationCode)).expires_at = utc_now() - timedelta(seconds=1)
        elif mutation == 'revoked':
            session.revoked_at = utc_now()
        elif mutation in {'idle', 'maximum'}:
            setattr(session, 'idle_expires_at' if mutation == 'idle' else 'max_expires_at', utc_now())
        elif mutation == 'user':
            db.session.scalar(select(User)).enabled = False
        else:
            db.session.scalar(select(Client)).standard_flow_enabled = False
        db.session.commit()
    response = exchange(client, raw)
    assert response.status_code == 400
    assert response.json == {'error': 'invalid_grant'}
    with app.app_context():
        assert db.session.scalar(select(AuthorizationCode)).consumed_at is None
        assert db.session.scalar(select(RefreshToken)) is None


def test_signing_failure_rolls_back_consumption_and_refresh(app, client):
    raw = returned_code(issue(client))
    with app.app_context():
        db.session.scalar(select(RealmKey)).active = False
        db.session.commit()
    response = exchange(client, raw)
    assert response.status_code == 503
    assert response.json == {'error': 'temporarily_unavailable'}
    with app.app_context():
        assert db.session.scalar(select(AuthorizationCode)).consumed_at is None
        assert db.session.scalar(select(RefreshToken)) is None
        db.session.scalar(select(RealmKey)).active = True
        db.session.commit()
    assert exchange(client, raw).status_code == 200


def test_code_cannot_be_exchanged_by_other_client_or_realm(app, client):
    from mini_keycloak.repositories.identity import IdentityRepository
    raw = returned_code(issue(client))
    with app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.get_realm('demo')
        repository.create_client(realm.id, 'other', redirect_uris=[PARAMS['redirect_uri']])
        other_realm = repository.create_realm('other')
        repository.create_client(other_realm.id, 'demo-app', redirect_uris=[PARAMS['redirect_uri']])
        db.session.commit()
    assert exchange(client, raw, client_id='other').json == {'error': 'invalid_grant'}
    response = client.post(TOKEN.replace('/demo/', '/other/'), data=dict(
        grant_type='authorization_code', client_id='demo-app', code=raw,
        redirect_uri=PARAMS['redirect_uri'], code_verifier=VERIFIER))
    assert response.json == {'error': 'invalid_grant'}
    assert exchange(client, raw).status_code == 200


def test_existing_public_password_grant_remains_available(client):
    response = client.post(TOKEN, data=dict(grant_type='password', client_id='demo-app',
                                          username='demo-user', password='DemoPassw0rd!'))
    assert response.status_code == 200
    assert response.json['access_token']
    assert response.json['token_type'] == 'Bearer'


def test_unexpected_issuance_failure_rolls_back_all_artifacts_and_returns_safe_json(app, client, monkeypatch):
    from mini_keycloak.services.tokens import TokenService
    raw = returned_code(issue(client))
    original = TokenService.issue

    def fail_after_flush(service, **kwargs):
        original(service, **kwargs)
        raise RuntimeError('secret-must-not-leak')

    with monkeypatch.context() as patch:
        patch.setattr(TokenService, 'issue', fail_after_flush)
        response = exchange(client, raw)
    assert response.status_code == 500
    assert response.json == {'error': 'server_error'}
    assert 'secret-must-not-leak' not in response.text
    assert response.headers['Cache-Control'] == 'no-store'
    with app.app_context():
        assert db.session.scalar(select(AuthorizationCode)).consumed_at is None
        assert db.session.scalar(select(RefreshToken)) is None
    assert exchange(client, raw).status_code == 200


def test_concurrent_token_requests_commit_exactly_one_refresh_family(app, client, monkeypatch):
    from mini_keycloak.repositories.protocol import AuthorizationCodeRepository
    raw = returned_code(issue(client))
    barrier = Barrier(2, timeout=10)
    original = AuthorizationCodeRepository.consume

    def synchronized(repository, *args, **kwargs):
        barrier.wait()
        return original(repository, *args, **kwargs)

    monkeypatch.setattr(AuthorizationCodeRepository, 'consume', synchronized)

    def request_tokens(_):
        with app.test_client() as worker:
            response = exchange(worker, raw)
            return response.status_code, response.json

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(request_tokens, range(2)))
    assert sorted(status for status, _ in responses) == [200, 400]
    assert [body for status, body in responses if status == 400] == [{'error': 'invalid_grant'}]
    with app.app_context():
        assert len(db.session.scalars(select(RefreshToken)).all()) == 1
        assert db.session.scalar(select(AuthorizationCode)).consumed_at is not None
