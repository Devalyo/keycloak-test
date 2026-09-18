import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationSession, AuthorizationCode, Client, UserSession
from mini_keycloak.models.identity import utc_now
from tests.helpers import form_action


AUTH = '/realms/demo/protocol/openid-connect/auth'
VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
PARAMS = dict(client_id='demo-app', redirect_uri='http://localhost:9999/callback',
              response_type='code', scope='openid profile email', state=' +&雪%2F',
              nonce='nonce-value', code_challenge=CHALLENGE, code_challenge_method='S256')


def issue(client, **overrides):
    page = client.get(AUTH, query_string=PARAMS | overrides)
    action = form_action(page.text, 'login-actions/authenticate')
    return client.post(action, data=dict(username='demo-user', password='DemoPassw0rd!'))


def returned_code(response):
    assert response.status_code == 302
    return parse_qs(urlsplit(response.location).query)['code'][0]


def test_login_issues_hashed_code_bound_to_complete_request(app, client):
    response = issue(client)
    raw = returned_code(response)
    assert re.fullmatch(r'[A-Za-z0-9_-]{43}', raw)
    assert parse_qs(urlsplit(response.location).query)['state'] == [PARAMS['state']]
    with app.app_context():
        code = db.session.scalar(select(AuthorizationCode))
        auth = db.session.scalar(select(AuthenticationSession))
        user_session = db.session.scalar(select(UserSession))
        assert code.code_hash == hashlib.sha256(raw.encode()).hexdigest()
        assert raw not in vars(code).values()
        assert (code.realm_id, code.client_id, code.user_id, code.user_session_id) == (
            auth.realm_id, auth.client_id, user_session.user_id, user_session.id)
        for field in ('redirect_uri', 'scope', 'nonce', 'code_challenge', 'code_challenge_method'):
            assert getattr(code, field) == PARAMS[field]
        assert 0 < (code.expires_at - utc_now()).total_seconds() <= 60
        assert code.consumed_at is None


def test_cookie_reuse_issues_distinct_codes_for_same_user_session(app, client):
    first = returned_code(issue(client))
    second_response = client.get(AUTH, query_string=PARAMS | {'state': 'second'})
    second = returned_code(second_response)
    assert second != first
    assert parse_qs(urlsplit(second_response.location).query)['state'] == ['second']
    with app.app_context():
        codes = db.session.scalars(select(AuthorizationCode)).all()
        assert len(codes) == 2
        assert len({code.user_session_id for code in codes}) == 1


def test_redirect_keeps_registered_query_and_omits_absent_state(app, client):
    redirect_uri = 'https://example.test/cb?existing=one%20two'
    with app.app_context():
        db.session.scalar(select(Client)).redirect_uris = [redirect_uri]
        db.session.commit()
    response = issue(client, redirect_uri=redirect_uri, state=None)
    returned_code(response)
    assert response.location.startswith(redirect_uri + '&code=')
    assert 'state' not in parse_qs(urlsplit(response.location).query)


def test_code_lifetime_uses_realm_override(app, client):
    with app.app_context():
        db.session.scalar(select(Client)).realm.authorization_code_lifetime_seconds = 9
        db.session.commit()
    returned_code(issue(client))
    with app.app_context():
        code = db.session.scalar(select(AuthorizationCode))
        assert (code.expires_at - code.created_at).total_seconds() == 9


def consume(session, raw, **overrides):
    from mini_keycloak.services.authorization import AuthorizationService
    code = session.scalar(select(AuthorizationCode))
    parameters = dict(realm_id=code.realm_id, client_id=code.client_id,
                      redirect_uri=code.redirect_uri, code_verifier=VERIFIER)
    return AuthorizationService(session, lifetime_seconds=60).consume(raw, **(parameters | overrides))


def test_matching_rfc7636_verifier_consumes_code_once(app, client):
    from mini_keycloak.oidc.errors import InvalidGrant
    raw = returned_code(issue(client))
    with app.app_context():
        code = consume(db.session, raw)
        assert code.consumed_at is not None
        db.session.commit()
        with pytest.raises(InvalidGrant):
            consume(db.session, raw)
        assert db.session.scalar(select(func.count()).select_from(AuthorizationCode)) == 1


@pytest.mark.parametrize('overrides', [
    {'code_verifier': None}, {'code_verifier': ''}, {'code_verifier': 'x' * 42},
    {'code_verifier': 'x' * 129}, {'code_verifier': '!' * 43},
    {'code_verifier': '雪' * 43}, {'code_verifier': 'x' * 43},
    {'realm_id': 'other'}, {'client_id': 'other'},
    {'redirect_uri': 'http://localhost:9999/callback/'},
])
def test_failed_exchange_cannot_consume_bound_code(app, client, overrides):
    from mini_keycloak.oidc.errors import InvalidGrant
    raw = returned_code(issue(client))
    with app.app_context():
        with pytest.raises(InvalidGrant) as failure:
            consume(db.session, raw, **overrides)
        assert failure.value.error == 'invalid_grant'
        assert db.session.scalar(select(AuthorizationCode)).consumed_at is None
        assert consume(db.session, raw).consumed_at is not None


@pytest.mark.parametrize('invalid_code', ['', 'unknown', '雪' * 43])
def test_unknown_code_returns_typed_generic_error(app, client, invalid_code):
    from mini_keycloak.oidc.errors import InvalidGrant
    returned_code(issue(client))
    with app.app_context():
        with pytest.raises(InvalidGrant):
            consume(db.session, invalid_code)


@pytest.mark.parametrize('mutation', ['expired', 'revoked', 'idle', 'maximum',
                                      'realm', 'client', 'user', 'standard_flow', 'pkce_method'])
def test_ineligible_grant_or_identity_cannot_be_consumed(app, client, mutation):
    from mini_keycloak.models import Realm, User
    from mini_keycloak.oidc.errors import InvalidGrant
    raw = returned_code(issue(client))
    with app.app_context():
        code = db.session.scalar(select(AuthorizationCode))
        user_session = db.session.scalar(select(UserSession))
        if mutation == 'expired':
            code.expires_at = utc_now() - timedelta(seconds=1)
        elif mutation == 'revoked':
            user_session.revoked_at = utc_now()
        elif mutation in {'idle', 'maximum'}:
            setattr(user_session, 'idle_expires_at' if mutation == 'idle' else 'max_expires_at',
                    utc_now() - timedelta(seconds=1))
        elif mutation == 'pkce_method':
            code.code_challenge_method = 'plain'
        else:
            model = {'realm': Realm, 'client': Client, 'user': User, 'standard_flow': Client}[mutation]
            setattr(db.session.scalar(select(model)),
                    'standard_flow_enabled' if mutation == 'standard_flow' else 'enabled', False)
        db.session.commit()
        with pytest.raises(InvalidGrant):
            consume(db.session, raw)
        assert db.session.scalar(select(AuthorizationCode)).consumed_at is None


def test_optional_pkce_normal_login_can_exchange_without_verifier(app, client):
    raw = returned_code(issue(client, code_challenge=None, code_challenge_method=None))
    with app.app_context():
        assert consume(db.session, raw, code_verifier=None).consumed_at is not None


@pytest.mark.parametrize('verifier', ['', VERIFIER], ids=['empty', 'nonempty'])
def test_optional_pkce_rejects_supplied_verifier_without_consuming_code(app, client, verifier):
    from mini_keycloak.oidc.errors import InvalidGrant
    raw = returned_code(issue(client, code_challenge=None, code_challenge_method=None))
    with app.app_context():
        with pytest.raises(InvalidGrant) as failure:
            consume(db.session, raw, code_verifier=verifier)
        assert failure.value.error == 'invalid_grant'
        assert not db.session().in_transaction()
        assert db.session.scalar(select(AuthorizationCode)).consumed_at is None
        assert consume(db.session, raw, code_verifier=None).consumed_at is not None
        db.session.commit()
        with pytest.raises(InvalidGrant):
            consume(db.session, raw, code_verifier=None)


def test_consumption_can_rollback_with_failed_token_transaction(app, client):
    raw = returned_code(issue(client))
    with app.app_context():
        consume(db.session, raw)
        db.session.rollback()
        assert db.session.scalar(select(AuthorizationCode)).consumed_at is None
        consume(db.session, raw)
        db.session.commit()


def test_concurrent_consumption_has_one_winner_and_rolls_back_loser(app, client, monkeypatch):
    from mini_keycloak.oidc.errors import InvalidGrant
    from mini_keycloak.repositories.protocol import AuthorizationCodeRepository
    raw = returned_code(issue(client))
    barrier = Barrier(2, timeout=10)
    original_consume = AuthorizationCodeRepository.consume

    def wait_for_both_readers(repository, *args, **kwargs):
        barrier.wait()
        return original_consume(repository, *args, **kwargs)

    monkeypatch.setattr(AuthorizationCodeRepository, 'consume', wait_for_both_readers)
    with app.app_context():
        engine = db.engine

    def exchange(index):
        with Session(engine, autoflush=False) as session:
            # This pending change must commit only for the winning exchange.
            session.scalar(select(Client)).name = f'exchange-{index}'
            try:
                consume(session, raw)
                session.commit()
                return 'winner'
            except InvalidGrant:
                assert not session.in_transaction()
                assert session.scalar(select(Client.name)) == f'exchange-{1 - index}'
                return 'loser'

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(exchange, range(2))) == ['loser', 'winner']


@pytest.mark.parametrize('changes', [
    {'response_type': 'token'}, {'scope': 'openid admin'},
    {'code_challenge_method': 'plain'}, {'code_challenge': 'bad'},
])
def test_authorization_error_redirects_only_to_validated_uri(app, client, changes):
    response = client.get(AUTH, query_string=PARAMS | changes)
    assert response.status_code == 302
    assert response.location.startswith(PARAMS['redirect_uri'] + '?')
    assert parse_qs(urlsplit(response.location).query) == {
        'error': ['invalid_request'], 'state': [PARAMS['state']]}
    with app.app_context():
        assert db.session.scalar(select(func.count()).select_from(AuthenticationSession)) == 0


@pytest.mark.parametrize('changes', [
    {'client_id': 'unknown'}, {'redirect_uri': 'https://untrusted.test/cb'},
])
def test_untrusted_authorization_destination_stays_local(client, changes):
    response = client.get(AUTH, query_string=PARAMS | changes)
    assert response.status_code == 400
    assert 'Location' not in response.headers
    assert 'nonce-value' not in response.text


def test_disabled_standard_flow_has_typed_authorization_error(app, client):
    with app.app_context():
        db.session.scalar(select(Client)).standard_flow_enabled = False
        db.session.commit()
    response = client.get(AUTH, query_string=PARAMS)
    assert response.status_code == 302
    assert parse_qs(urlsplit(response.location).query)['error'] == ['unauthorized_client']


def test_issuer_rejects_repeated_authentication_handoff(app, client):
    from mini_keycloak.oidc.errors import AccessDenied
    from mini_keycloak.services.authorization import AuthorizationService
    from mini_keycloak.services.sessions import BrowserAuthenticationResult
    returned_code(issue(client))
    with app.app_context():
        result = BrowserAuthenticationResult(db.session.scalar(select(AuthenticationSession)),
                                             db.session.scalar(select(UserSession)))
        with pytest.raises(AccessDenied):
            AuthorizationService(db.session, lifetime_seconds=60).issue(result)
        assert db.session.scalar(select(func.count()).select_from(AuthorizationCode)) == 1


@pytest.mark.parametrize('mutation', ['revoked', 'wrong_realm', 'expired_auth', 'disabled_user'])
def test_issuer_rejects_ineligible_authentication_handoff(app, client, mutation):
    from mini_keycloak.models import User
    from mini_keycloak.oidc.errors import AccessDenied
    from mini_keycloak.services.authorization import AuthorizationService
    from mini_keycloak.services.sessions import BrowserAuthenticationResult
    returned_code(issue(client))
    # A fresh ordinary authorization request is paired with an invalid session.
    other_browser = app.test_client()
    other_browser.get(AUTH, query_string=PARAMS)
    with app.app_context():
        auth = db.session.scalar(select(AuthenticationSession).where(
            AuthenticationSession.current_execution == 'choose-user'))
        user_session = db.session.scalar(select(UserSession))
        if mutation == 'revoked':
            user_session.revoked_at = utc_now()
        elif mutation == 'wrong_realm':
            from mini_keycloak.repositories.identity import IdentityRepository
            user_session.realm_id = IdentityRepository(db.session).create_realm('other').id
        elif mutation == 'expired_auth':
            auth.expires_at = utc_now() - timedelta(seconds=1)
        else:
            db.session.scalar(select(User)).enabled = False
        db.session.commit()
        with pytest.raises(AccessDenied):
            AuthorizationService(db.session, lifetime_seconds=60).issue(
                BrowserAuthenticationResult(auth, user_session))
        assert db.session.scalar(select(func.count()).select_from(AuthorizationCode)) == 1
