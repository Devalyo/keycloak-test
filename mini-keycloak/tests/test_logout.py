from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from sqlalchemy import delete, select, update
from werkzeug.datastructures import MultiDict

from mini_keycloak.authentication.browser import COOKIE_NAME
from mini_keycloak.extensions import db
from mini_keycloak.models import AuthorizationCode, Client, Realm, RealmKey, RefreshToken, SecurityEvent, User, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.identity import IdentityRepository
from tests.test_authorization_code import AUTH, PARAMS, returned_code
from tests.test_client_authentication import SECRET, basic, confidential
from tests.test_jwt_tokens import issued, service
from tests.test_refresh_tokens import refresh
from tests.test_token_endpoint import exchange
from tests.test_userinfo import USERINFO, bearer, signed_variant


LOGOUT = '/realms/demo/protocol/openid-connect/logout'
DESTINATION = 'https://app.example.test/signed-out?existing=one%20two'
SSO_DESTINATION = 'https://second.example.test/signed-out'


def sso_tokens(app, client):
    first = issued(client)
    with app.app_context():
        origin = db.session.scalar(select(Client))
        origin.post_logout_redirect_uris = [DESTINATION]
        second = IdentityRepository(db.session).create_client(
            origin.realm_id, 'second-app', redirect_uris=[PARAMS['redirect_uri']])
        second.post_logout_redirect_uris = [SSO_DESTINATION]
        db.session.commit()
    authorization = client.get(AUTH, query_string=PARAMS | {'client_id': 'second-app'})
    response = exchange(client, returned_code(authorization), client_id='second-app')
    assert response.status_code == 200
    second = response.json
    assert first['session_state'] == second['session_state']
    with app.app_context():
        sessions = db.session.scalars(select(UserSession)).all()
        assert len(sessions) == 1
        assert db.session.get(Client, sessions[0].client_id).client_id == 'demo-app'
    return first, second


@pytest.mark.parametrize('method', ['get', 'post'])
@pytest.mark.parametrize('expired', [False, True])
@pytest.mark.parametrize('destination', [SSO_DESTINATION, DESTINATION, SSO_DESTINATION + '/'])
def test_subsequent_sso_client_hint_revokes_shared_session_and_supports_retry(
        app, client, method, expired, destination):
    first, second = sso_tokens(app, client)
    raw = signed_variant(app, second['id_token'], exp=1) if expired else second['id_token']
    for tokens in (first, second):
        assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 200
    params = {'id_token_hint': raw, 'post_logout_redirect_uri': destination, 'state': ' +&雪%2F'}
    previous = None
    for retry in (False, True):
        if retry:
            params['client_id'] = 'second-app'
        response = getattr(client, method)(LOGOUT, **{
            'query_string' if method == 'get' else 'data': params})
        assert response.status_code == (302 if destination == SSO_DESTINATION else 200)
        if destination == SSO_DESTINATION:
            assert response.location.startswith(SSO_DESTINATION + '?')
            assert parse_qs(urlsplit(response.location).query) == {'state': [' +&雪%2F']}
        else:
            assert 'Location' not in response.headers
        assert client.get_cookie(COOKIE_NAME, path='/realms/demo/') is None
        with app.app_context():
            revoked_at = db.session.scalar(select(UserSession.revoked_at))
            families = dict(db.session.execute(select(RefreshToken.id, RefreshToken.revoked_at)).all())
            assert revoked_at is not None
            assert len(families) == 2 and all(families.values())
            if retry:
                assert (revoked_at, families) == previous
            previous = (revoked_at, families)
    for tokens, audience in ((first, 'demo-app'), (second, 'second-app')):
        assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 401
        assert refresh(client, tokens['refresh_token'], client_id=audience).json == {'error': 'invalid_grant'}


@pytest.mark.parametrize('expired', [False, True])
@pytest.mark.parametrize('mutation', [
    'audience_disabled', 'audience_realm', 'unknown_audience', 'origin_disabled', 'origin_realm',
    'foreign_origin', 'client_parameter', 'azp', 'subject', 'sid', 'auth_time', 'signature',
])
def test_subsequent_sso_client_hint_requires_trusted_claims_and_both_clients(app, client, expired, mutation):
    _, second = sso_tokens(app, client)
    raw = signed_variant(app, second['id_token'], exp=1) if expired else second['id_token']
    with app.app_context():
        identities = IdentityRepository(db.session)
        realm = db.session.scalar(select(Realm))
        origin = identities.get_client(realm.id, 'demo-app')
        audience = identities.get_client(realm.id, 'second-app')
        if mutation in {'audience_disabled', 'origin_disabled'}:
            (audience if mutation == 'audience_disabled' else origin).enabled = False
        elif mutation in {'audience_realm', 'origin_realm', 'foreign_origin'}:
            other = identities.create_realm('other')
            if mutation == 'foreign_origin':
                foreign = identities.create_client(other.id, 'demo-app', redirect_uris=[])
                db.session.scalar(select(UserSession)).client_id = foreign.id
            else:
                (audience if mutation == 'audience_realm' else origin).realm_id = other.id
        db.session.commit()
    if mutation == 'unknown_audience':
        raw = signed_variant(app, raw, aud='unknown', azp='unknown')
    elif mutation in {'azp', 'subject', 'sid', 'auth_time'}:
        raw = signed_variant(app, raw, **{
            {'subject': 'sub'}.get(mutation, mutation): 1 if mutation == 'auth_time' else 'unknown'})
    elif mutation == 'signature':
        from cryptography.hazmat.primitives.asymmetric import rsa
        claims = jwt.decode(raw, options={'verify_signature': False})
        raw = jwt.encode(claims, rsa.generate_private_key(public_exponent=65537, key_size=2048),
                         algorithm='RS256', headers=jwt.get_unverified_header(raw))
    params = {'id_token_hint': raw, 'post_logout_redirect_uri': SSO_DESTINATION}
    if mutation == 'client_parameter':
        params['client_id'] = 'demo-app'
    response = client.get(LOGOUT, query_string=params)
    assert (response.status_code, response.json) == (401, {'error': 'invalid_token'})
    assert 'Location' not in response.headers and 'Set-Cookie' not in response.headers
    with app.app_context():
        assert db.session.scalar(select(UserSession.revoked_at)) is None
        assert all(row.revoked_at is None for row in db.session.scalars(select(RefreshToken)))


def allow_redirect(app):
    with app.app_context():
        db.session.scalar(select(Client)).post_logout_redirect_uris = [DESTINATION]
        db.session.commit()


@pytest.mark.parametrize('method', ['get', 'post'])
def test_expired_id_hint_revokes_active_session(app, client, method):
    tokens = issued(client)
    allow_redirect(app)
    expired = signed_variant(app, tokens['id_token'], exp=1)
    assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 200
    response = getattr(client, method)(LOGOUT, **{
        'query_string' if method == 'get' else 'data': {
            'id_token_hint': expired, 'post_logout_redirect_uri': DESTINATION}})
    assert response.status_code == 302
    assert response.location.startswith(DESTINATION)
    assert parse_qs(urlsplit(response.location).query) == {'existing': ['one two']}
    assert client.get_cookie(COOKIE_NAME, path='/realms/demo/') is None
    assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 401
    assert refresh(client, tokens['refresh_token']).json == {'error': 'invalid_grant'}
    with app.app_context():
        assert db.session.scalar(select(UserSession)).revoked_at is not None
        assert all(row.revoked_at is not None for row in db.session.scalars(select(RefreshToken)))


@pytest.mark.parametrize('expired', [False, True])
@pytest.mark.parametrize('destination', [None, DESTINATION, DESTINATION + '/'])
def test_repeated_rp_logout_succeeds_without_changing_revocation(app, client, expired, destination):
    tokens = issued(client)
    allow_redirect(app)
    assert client.post(LOGOUT, data={'id_token_hint': tokens['id_token']}).status_code == 200
    with app.app_context():
        first_revocation = db.session.scalar(select(UserSession.revoked_at))
        first_family_revocations = list(db.session.scalars(select(RefreshToken.revoked_at)))
    raw = signed_variant(app, tokens['id_token'], exp=1) if expired else tokens['id_token']
    response = client.get(LOGOUT, query_string={
        'id_token_hint': raw, 'post_logout_redirect_uri': destination, 'state': ' +&雪%2F'})
    assert response.status_code == (302 if destination == DESTINATION else 200)
    if destination == DESTINATION:
        assert parse_qs(urlsplit(response.location).query) == {
            'existing': ['one two'], 'state': [' +&雪%2F']}
    else:
        assert 'Location' not in response.headers
    with app.app_context():
        assert db.session.scalar(select(UserSession.revoked_at)) == first_revocation
        assert list(db.session.scalars(select(RefreshToken.revoked_at))) == first_family_revocations
    assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 401


@pytest.mark.parametrize('kind,typ', [('access_token', 'Bearer'), ('id_token', 'ID'), ('refresh_token', 'Refresh')])
def test_normal_token_verification_still_rejects_expiration(app, client, kind, typ):
    from mini_keycloak.oidc.errors import InvalidToken
    raw = signed_variant(app, issued(client)[kind], exp=1)
    with app.app_context():
        with pytest.raises(InvalidToken):
            service(app).verify_presented(raw, realm=db.session.scalar(select(Realm)), token_type=typ)


@pytest.mark.parametrize('revoked', [False, True])
@pytest.mark.parametrize('mutation', [
    'signature', 'kid', 'algorithm', 'missing_exp', 'invalid_exp', 'issuer', 'audience',
    'azp', 'type', 'subject', 'sid', 'auth_time', 'future_iat', 'future_nbf',
])
def test_expired_logout_hint_keeps_signature_and_claim_checks(app, client, revoked, mutation):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from mini_keycloak.security.key_encryption import decrypt_private_pem
    tokens = issued(client)
    allow_redirect(app)
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        if revoked:
            session.revoked_at = utc_now() - timedelta(seconds=1)
            db.session.commit()
        previous = session.revoked_at
        key = db.session.scalar(select(RealmKey))
        signing_key = decrypt_private_pem(key.encrypted_private_pem, app.config['OIDC_KEY_ENCRYPTION_SECRET'])
        claims = jwt.decode(tokens['id_token'], options={'verify_signature': False}) | {'exp': 1}
        algorithm, headers = 'RS256', {'kid': key.kid}
        if mutation == 'signature':
            signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif mutation == 'kid':
            headers['kid'] = 'unknown'
        elif mutation == 'algorithm':
            algorithm, signing_key = 'HS256', 'untrusted-signing-secret-32-bytes-long'
        elif mutation == 'missing_exp':
            del claims['exp']
        else:
            field, value = {
                'invalid_exp': ('exp', 'invalid'), 'issuer': ('iss', 'https://other.test'),
                'audience': ('aud', ['demo-app', 'other']), 'azp': ('azp', 'other'),
                'type': ('typ', 'Bearer'), 'subject': ('sub', 'unknown'), 'sid': ('sid', 'unknown'),
                'auth_time': ('auth_time', 1),
                'future_iat': ('iat', int(utc_now().timestamp()) + 3600),
                'future_nbf': ('nbf', int(utc_now().timestamp()) + 3600),
            }[mutation]
            claims[field] = value
        raw = jwt.encode(claims, signing_key, algorithm=algorithm, headers=headers)
    response = client.get(LOGOUT, query_string={
        'id_token_hint': raw, 'post_logout_redirect_uri': DESTINATION})
    assert (response.status_code, response.json) == (401, {'error': 'invalid_token'})
    assert 'Location' not in response.headers and 'Set-Cookie' not in response.headers
    with app.app_context():
        assert db.session.scalar(select(UserSession.revoked_at)) == previous


@pytest.mark.parametrize('revoked', [False, True])
@pytest.mark.parametrize('mutation', [
    'realm', 'client', 'user', 'idle', 'maximum', 'deleted_session', 'session_client',
    'session_user', 'session_realm', 'client_realm', 'user_realm',
])
def test_expired_logout_hint_requires_existing_matching_state(app, client, mutation, revoked):
    from mini_keycloak.repositories.identity import IdentityRepository
    tokens = issued(client)
    allow_redirect(app)
    raw = signed_variant(app, tokens['id_token'], exp=1)
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        if revoked:
            session.revoked_at = utc_now() - timedelta(seconds=1)
        previous = session.revoked_at
        if mutation in {'realm', 'client', 'user'}:
            db.session.scalar(select({'realm': Realm, 'client': Client, 'user': User}[mutation])).enabled = False
        elif mutation in {'idle', 'maximum'}:
            setattr(session, 'idle_expires_at' if mutation == 'idle' else 'max_expires_at',
                    utc_now() - timedelta(seconds=1))
        elif mutation == 'deleted_session':
            db.session.execute(delete(AuthorizationCode))
            db.session.execute(delete(RefreshToken))
            db.session.execute(update(SecurityEvent).where(SecurityEvent.user_session_id == session.id)
                               .values(user_session_id=None))
            db.session.delete(session)
        else:
            identities = IdentityRepository(db.session)
            other_realm = identities.create_realm('other')
            if mutation == 'session_client':
                other_client = identities.create_client(other_realm.id, 'other-client', redirect_uris=[])
                session.client_id = other_client.id
            elif mutation == 'session_user':
                other_user = identities.create_user(session.realm_id, 'other', 'other@example.test', 'secret')
                session.user_id = other_user.id
            elif mutation == 'session_realm':
                session.realm_id = other_realm.id
            else:
                db.session.scalar(select(Client if mutation == 'client_realm' else User)).realm_id = other_realm.id
        db.session.commit()
    response = client.get(LOGOUT, query_string={
        'id_token_hint': raw, 'post_logout_redirect_uri': DESTINATION})
    assert response.status_code == (404 if mutation == 'realm' else 401)
    assert 'Location' not in response.headers and 'Set-Cookie' not in response.headers
    with app.app_context():
        assert db.session.scalar(select(UserSession.revoked_at)) == (
            None if mutation == 'deleted_session' else previous)


@pytest.mark.parametrize('method', ['get', 'post'])
def test_rp_logout_revokes_session_families_clears_cookie_and_preserves_state(app, client, method):
    tokens = issued(client)
    unrelated = issued(app.test_client())
    rotated = refresh(client, tokens['refresh_token']).json
    allow_redirect(app)
    state = ' +&雪%2F'
    params = dict(id_token_hint=tokens['id_token'], client_id='demo-app',
                  post_logout_redirect_uri=DESTINATION, state=state)
    client.set_cookie(COOKIE_NAME, 'other-realm-cookie', path='/realms/other/')
    response = getattr(client, method)(LOGOUT, **{'query_string' if method == 'get' else 'data': params})
    assert response.status_code == 302
    assert response.location.startswith(DESTINATION + '&')
    assert parse_qs(urlsplit(response.location).query) == {'existing': ['one two'], 'state': [state]}
    assert client.get_cookie(COOKIE_NAME, path='/realms/demo/') is None
    assert client.get_cookie(COOKIE_NAME, path='/realms/other/').value == 'other-realm-cookie'
    assert response.headers['Cache-Control'] == 'no-store'
    assert client.get(USERINFO, headers=bearer(rotated['access_token'])).status_code == 401
    assert refresh(client, rotated['refresh_token']).json == {'error': 'invalid_grant'}
    with app.app_context():
        session = db.session.scalar(select(UserSession).where(UserSession.sid == tokens['session_state']))
        rows = db.session.scalars(select(RefreshToken).where(RefreshToken.user_session_id == session.id)).all()
        assert len(rows) == 2 and all(row.revoked_at is not None for row in rows)
        assert session.revoked_at is not None
    assert refresh(client, unrelated['refresh_token']).status_code == 200


@pytest.mark.parametrize('destination', [None, '', 'https://untrusted.test', DESTINATION + '/',
                                        DESTINATION + '#fragment', 'http://localhost:9999/callback'])
def test_valid_hint_with_invalid_or_missing_redirect_logs_out_locally(app, client, destination):
    tokens = issued(client)
    allow_redirect(app)
    response = client.get(LOGOUT, query_string=dict(id_token_hint=tokens['id_token'],
        post_logout_redirect_uri=destination, state='do-not-reflect'))
    assert response.status_code == 200
    assert 'Location' not in response.headers and 'do-not-reflect' not in response.text
    assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 401


@pytest.mark.parametrize('mutation', ['missing', 'malformed', 'access', 'issuer', 'subject', 'sid',
                                      'audience', 'client'])
def test_untrusted_logout_hint_or_client_cannot_redirect_or_revoke(app, client, mutation):
    tokens = issued(client)
    allow_redirect(app)
    raw = tokens['id_token']
    if mutation == 'missing':
        raw = None
    elif mutation == 'malformed':
        raw = 'invalid'
    elif mutation == 'access':
        raw = tokens['access_token']
    elif mutation != 'client':
        field = {'issuer': 'iss', 'subject': 'sub', 'audience': 'aud', 'expired': 'exp'}.get(mutation, mutation)
        raw = signed_variant(app, raw, **{field: 1 if field == 'exp' else 'other'})
    response = client.get(LOGOUT, query_string=dict(id_token_hint=raw,
        client_id='other' if mutation == 'client' else 'demo-app', post_logout_redirect_uri=DESTINATION))
    assert response.status_code in {200, 400, 401}
    assert 'Location' not in response.headers and 'Set-Cookie' not in response.headers
    assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 200


def test_logout_rejects_duplicate_or_mixed_request_parameters(client):
    tokens = issued(client)
    for options in [
        {'query_string': MultiDict([('id_token_hint', tokens['id_token']), ('id_token_hint', tokens['id_token'])])},
        {'query_string': {'id_token_hint': tokens['id_token']}, 'data': {'state': 'mixed'}},
        {'data': {'id_token_hint': tokens['id_token'], 'refresh_token': tokens['refresh_token'], 'client_id': 'demo-app'}},
    ]:
        response = client.post(LOGOUT, **options)
        assert response.status_code == 400
        assert 'Location' not in response.headers
        assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 200


@pytest.mark.parametrize('method', ['public', 'post', 'basic'])
def test_legacy_logout_authenticates_client_and_revokes_session(app, client, method):
    tokens = issued(client)
    data = dict(refresh_token=tokens['refresh_token'])
    headers = {}
    if method != 'public':
        confidential(app)
        rejected = client.post(LOGOUT, data=data | {'client_id': 'demo-app'})
        assert (rejected.status_code, rejected.json) == (401, {'error': 'invalid_client'})
        assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 200
    if method == 'basic':
        headers = basic()
    else:
        data['client_id'] = 'demo-app'
        if method == 'post':
            data['client_secret'] = SECRET
    response = client.post(LOGOUT, data=data, headers=headers)
    assert response.status_code == 204
    assert client.get_cookie(COOKIE_NAME, path='/realms/demo/') is None
    assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 401
    assert refresh(client, tokens['refresh_token'], **({'client_secret': SECRET} if method != 'public' else {})).json == {'error': 'invalid_grant'}


@pytest.mark.parametrize('kind', ['access_token', 'id_token', 'malformed', 'wrong_client'])
def test_legacy_logout_rejects_unbound_tokens_without_revoking(app, client, kind):
    tokens = issued(client)
    with app.app_context():
        from mini_keycloak.repositories.identity import IdentityRepository
        realm_id = db.session.scalar(select(Client.realm_id))
        IdentityRepository(db.session).create_client(realm_id, 'other', redirect_uris=[])
        db.session.commit()
    raw = tokens['refresh_token'] if kind == 'wrong_client' else tokens.get(kind, 'invalid')
    response = client.post(LOGOUT, data=dict(refresh_token=raw, client_id='other' if kind == 'wrong_client' else 'demo-app'))
    assert (response.status_code, response.json) == (400, {'error': 'invalid_grant'})
    assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 200


def test_session_revocation_is_idempotent_and_covers_all_families(app, client):
    from mini_keycloak.services.sessions import revoke_session
    from tests.test_jwt_tokens import service
    from mini_keycloak.models import Realm
    issued(client)
    with app.app_context():
        session = db.session.scalar(select(UserSession))
        service(app).issue(realm=db.session.scalar(select(Realm)), client=db.session.scalar(select(Client)),
                           user_session=session, scope='openid')
        db.session.commit()
        revoke_session(db.session, session.sid, session.realm_id)
        db.session.commit()
        first = session.revoked_at
        revoke_session(db.session, session.sid, session.realm_id)
        db.session.commit()
        assert session.revoked_at == first and first is not None
        rows = db.session.scalars(select(RefreshToken)).all()
        assert len({row.family_id for row in rows}) == 2
        assert all(row.revoked_at == first for row in rows)


def test_logout_commit_failure_keeps_cookie_and_session(app, client, monkeypatch):
    tokens = issued(client)
    def fail_commit():
        raise RuntimeError('private-sentinel')
    monkeypatch.setattr(db.session, 'commit', fail_commit)
    response = client.post(LOGOUT, data={'id_token_hint': tokens['id_token']})
    assert (response.status_code, response.json) == (500, {'error': 'server_error'})
    assert 'Set-Cookie' not in response.headers
    assert client.get_cookie(COOKIE_NAME, path='/realms/demo/') is not None
    assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 200


def test_refresh_reuse_uses_session_revocation_for_all_families(app, client):
    from mini_keycloak.models import Realm
    from tests.test_jwt_tokens import service
    tokens = issued(client)
    with app.app_context():
        service(app).issue(realm=db.session.scalar(select(Realm)), client=db.session.scalar(select(Client)),
                           user_session=db.session.scalar(select(UserSession)), scope='openid')
        db.session.commit()
    assert refresh(client, tokens['refresh_token']).status_code == 200
    assert refresh(client, tokens['refresh_token']).json == {'error': 'invalid_grant'}
    with app.app_context():
        rows = db.session.scalars(select(RefreshToken)).all()
        assert len({row.family_id for row in rows}) == 2
        assert all(row.revoked_at is not None for row in rows)


def test_logout_racing_refresh_leaves_no_active_descendant(app, client, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from mini_keycloak.repositories.protocol import RefreshTokenRepository
    from mini_keycloak.repositories.sessions import UserSessionRepository
    tokens = issued(client)
    barrier = Barrier(2, timeout=10)
    lock_refresh = RefreshTokenRepository.lock_session
    revoke = UserSessionRepository.revoke

    def synchronized_refresh(repository, *args, **kwargs):
        barrier.wait()
        return lock_refresh(repository, *args, **kwargs)

    def synchronized_revoke(repository, *args, **kwargs):
        barrier.wait()
        return revoke(repository, *args, **kwargs)

    monkeypatch.setattr(RefreshTokenRepository, 'lock_session', synchronized_refresh)
    monkeypatch.setattr(UserSessionRepository, 'revoke', synchronized_revoke)

    def logout_request():
        with app.test_client() as worker:
            return worker.post(LOGOUT, data={'id_token_hint': tokens['id_token']}).status_code

    def refresh_request():
        with app.test_client() as worker:
            return refresh(worker, tokens['refresh_token']).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        logout_future = executor.submit(logout_request)
        refresh_future = executor.submit(refresh_request)
        assert logout_future.result() == 200
        assert refresh_future.result() in {200, 400}
    with app.app_context():
        assert db.session.scalar(select(UserSession)).revoked_at is not None
        assert all(row.revoked_at is not None for row in db.session.scalars(select(RefreshToken)))
    assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 401
