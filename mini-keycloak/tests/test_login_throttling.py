from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import importlib
from threading import Barrier
from types import SimpleNamespace

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.orm import Session

from mini_keycloak.app import create_app
from mini_keycloak.config import Settings
from mini_keycloak.extensions import db
from mini_keycloak.models import AuthorizationCode, Realm, RefreshToken, SecurityEvent, UserSession
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.security.passwords import PasswordService
from tests.helpers import form_action
from tests.test_browser_authentication import begin
from tests.test_client_authentication import TOKEN
from tests.test_password_grant import password_grant


NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)


def limiter(session, *, threshold=5, window_seconds=300, lock_seconds=60):
    module = importlib.import_module('mini_keycloak.security.login_throttling')
    return module.LoginThrottle(session, secret='test-secret', threshold=threshold,
                                window_seconds=window_seconds, lock_seconds=lock_seconds)


def bucket_model():
    from mini_keycloak.models import LoginFailureBucket
    return LoginFailureBucket


@pytest.mark.parametrize('name', ['LOGIN_FAILURE_THRESHOLD', 'LOGIN_FAILURE_WINDOW_SECONDS', 'LOGIN_LOCK_SECONDS'])
@pytest.mark.parametrize('value', [0, -1, False, 'no', '', '1.5'])
def test_limiter_settings_cannot_disable_or_silently_coerce(name, value, monkeypatch):
    with pytest.raises(ValueError, match='^MINI_KEYCLOAK_' + name + '$'):
        Settings().as_flask_config(overrides={name: value})
    monkeypatch.setenv('MINI_KEYCLOAK_' + name, str(value))
    with pytest.raises(ValueError, match='^MINI_KEYCLOAK_' + name + '$'):
        Settings.from_env()


def test_default_settings_are_typed_and_active():
    config = Settings.from_env().as_flask_config()
    assert (config['LOGIN_FAILURE_THRESHOLD'], config['LOGIN_FAILURE_WINDOW_SECONDS'],
            config['LOGIN_LOCK_SECONDS']) == (5, 300, 60)


def test_bucket_normalization_is_stable_private_and_isolated(app):
    with app.app_context():
        realm_id = db.session.scalar(select(Realm.id))
        throttle = limiter(db.session)
        digest = throttle.bucket_hash(realm_id, '  STRAẞE  ', '2001:0db8::1')
        assert digest == throttle.bucket_hash(realm_id, 'strasse', '2001:db8:0:0:0:0:0:1')
        assert len(digest) == 64 and set(digest) <= set('0123456789abcdef')
        assert digest != throttle.bucket_hash('other-realm', 'strasse', '2001:db8::1')
        assert digest != throttle.bucket_hash(realm_id, 'strasse', '2001:db8::2')
        assert digest != throttle.bucket_hash(realm_id, 'other', '2001:db8::1')
        assert throttle.bucket_hash(realm_id, 'x', None) == throttle.bucket_hash(realm_id, 'x', 'invalid')
        assert digest == limiter(db.session).bucket_hash(realm_id, 'strasse', '2001:db8::1')
        changed_secret = type(throttle)(db.session, secret='independent-secret', threshold=5,
                                       window_seconds=300, lock_seconds=60)
        assert digest != changed_secret.bucket_hash(realm_id, 'strasse', '2001:db8::1')
        throttle.record_failure(realm_id, digest, now=NOW)
        db.session.commit()
        row = db.session.execute(text('SELECT * FROM login_failure_buckets')).one()
        assert not any(value in str(row) for value in ['strasse', 'STRAẞE', '2001:', 'test-secret'])


def test_window_lock_expiration_and_matching_clear(app):
    with app.app_context():
        realm_id = db.session.scalar(select(Realm.id))
        throttle = limiter(db.session, threshold=2)
        digest = throttle.bucket_hash(realm_id, 'demo-user', '127.0.0.1')
        other = throttle.bucket_hash(realm_id, 'other', '127.0.0.1')
        throttle.record_failure(realm_id, digest, now=NOW)
        throttle.record_failure(realm_id, digest, now=NOW + timedelta(seconds=300))
        db.session.commit()
        row = db.session.scalar(select(bucket_model()))
        assert row.failure_count == 1
        assert row.first_failure_at == NOW + timedelta(seconds=300)
        throttle.record_failure(realm_id, digest, now=NOW + timedelta(seconds=301))
        db.session.commit()
        db.session.expire_all()
        assert row.failure_count == 2
        assert row.blocked_until == NOW + timedelta(seconds=361)
        assert throttle.is_blocked(realm_id, digest, now=NOW + timedelta(seconds=360))
        snapshot = (row.failure_count, row.last_failure_at, row.blocked_until, row.expires_at)
        throttle.record_failure(realm_id, digest, now=NOW + timedelta(seconds=359))
        db.session.commit()
        db.session.expire_all()
        assert (row.failure_count, row.last_failure_at, row.blocked_until, row.expires_at) == snapshot
        assert not throttle.is_blocked(realm_id, digest, now=NOW + timedelta(seconds=361))
        throttle.record_failure(realm_id, digest, now=NOW + timedelta(seconds=361))
        throttle.record_failure(realm_id, other, now=NOW + timedelta(seconds=361))
        db.session.commit()
        db.session.expire_all()
        assert row.failure_count == 1
        throttle.clear(realm_id, digest)
        db.session.commit()
        assert [r.bucket_hash for r in db.session.scalars(select(bucket_model()))] == [other]


@pytest.mark.parametrize('threshold,expected_count', [(100, 8), (3, 3)])
def test_sqlite_concurrent_failure_upserts_lose_no_counts(app, threshold, expected_count):
    with app.app_context():
        realm_id = db.session.scalar(select(Realm.id))
        engine = db.engine
        digest = limiter(db.session).bucket_hash(realm_id, 'demo-user', '127.0.0.1')
        db.session.rollback()
        barrier = Barrier(8)
        def fail(_):
            with Session(engine) as session:
                throttle = limiter(session, threshold=threshold)
                barrier.wait(timeout=10)
                throttle.record_failure(realm_id, digest, now=NOW)
                session.commit()
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(fail, range(8)))
        row = db.session.scalar(select(bucket_model()))
        assert row.failure_count == expected_count
        assert row.blocked_until == (NOW + timedelta(seconds=60) if threshold == 3 else None)


@pytest.mark.parametrize('username', ['demo-user', 'missing-person'])
def test_password_failures_survive_oauth_rollback_and_block_without_success(app, client, username, monkeypatch):
    app.config['LOGIN_FAILURE_THRESHOLD'] = 2
    for _ in range(2):
        response = password_grant(client, username=username, password='wrong')
        assert (response.status_code, response.json) == (400, {'error': 'invalid_grant'})
    with app.app_context():
        row = db.session.scalar(select(bucket_model()))
        assert row.failure_count == 2
        before = (row.failure_count, row.blocked_until, row.expires_at)
    checked = []
    original = PasswordService.verify
    def verify(self, encoded, raw):
        checked.append(encoded)
        return original(self, encoded, raw)
    monkeypatch.setattr(PasswordService, 'verify', verify)
    response = password_grant(client, username=username)
    assert (response.status_code, response.json) == (400, {'error': 'invalid_grant'})
    assert checked == [app.extensions['browser_dummy_hash']]
    with app.app_context():
        row = db.session.scalar(select(bucket_model()))
        assert (row.failure_count, row.blocked_until, row.expires_at) == before
        assert db.session.scalar(select(UserSession)) is None
        assert db.session.scalar(select(RefreshToken)) is None
        assert db.session.scalar(select(AuthorizationCode)) is None
        assert not db.session.scalars(select(SecurityEvent).where(SecurityEvent.event_type == 'PASSWORD_GRANT')).all()


def test_browser_and_password_grant_share_failure_bucket(app, client):
    app.config['LOGIN_FAILURE_THRESHOLD'] = 2
    action = form_action(begin(client).text, 'login-actions/authenticate')
    assert client.post(action, data={'username': ' DEMO-USER ', 'password': 'wrong'}).status_code == 401
    assert password_grant(client, password='wrong').status_code == 400
    response = client.post(action, data={'username': 'demo-user', 'password': 'DemoPassw0rd!'})
    assert response.status_code == 401
    assert 'Invalid username or password.' in response.text
    with app.app_context():
        assert db.session.scalar(select(bucket_model())).failure_count == 2
        assert db.session.scalar(select(UserSession)) is None
        assert db.session.scalar(select(AuthorizationCode)) is None
        assert not db.session.scalars(select(SecurityEvent).where(SecurityEvent.event_type == 'LOGIN')).all()


@pytest.mark.parametrize('browser', [False, True])
def test_success_clears_only_matching_bucket(app, client, browser):
    password_grant(client, password='wrong')
    password_grant(client, username='other', password='wrong')
    if browser:
        action = form_action(begin(client).text, 'login-actions/authenticate')
        assert client.post(action, data={'username': 'demo-user', 'password': 'DemoPassw0rd!'}).status_code == 302
    else:
        assert password_grant(client).status_code == 200
    with app.app_context():
        assert len(db.session.scalars(select(bucket_model())).all()) == 1


@pytest.mark.parametrize('operation', ['is_blocked', 'record_failure', 'clear'])
@pytest.mark.parametrize('browser', [False, True])
def test_limiter_outage_fails_closed_without_issuing_credentials(app, client, monkeypatch, caplog, operation, browser):
    throttle_type = type(limiter(db.session))
    def unavailable(*args, **kwargs):
        raise RuntimeError('PRIVATE-limiter-storage-parameters')
    monkeypatch.setattr(throttle_type, operation, unavailable)
    password = 'wrong' if operation == 'record_failure' else 'DemoPassw0rd!'
    if browser:
        action = form_action(begin(client).text, 'login-actions/authenticate')
        response = client.post(action, data={'username': 'demo-user', 'password': password})
    else:
        response = password_grant(client, password=password)
        assert response.json == {'error': 'server_error'}
    assert response.status_code == 500
    assert 'PRIVATE-limiter-storage-parameters' not in response.text + caplog.text
    with app.app_context():
        assert db.session.scalar(select(UserSession)) is None
        assert db.session.scalar(select(RefreshToken)) is None
        assert db.session.scalar(select(AuthorizationCode)) is None


def test_failed_token_issuance_preserves_bucket(app, client):
    from mini_keycloak.models import RealmKey
    password_grant(client, password='wrong')
    with app.app_context():
        db.session.scalar(select(RealmKey)).active = False
        db.session.commit()
    assert password_grant(client).status_code == 503
    with app.app_context():
        assert db.session.scalar(select(bucket_model())).failure_count == 1


def test_buckets_survive_application_restart(app, client):
    app.config['LOGIN_FAILURE_THRESHOLD'] = 1
    password_grant(client, password='wrong')
    restarted = create_app({'TESTING': True, 'SECRET_KEY': app.secret_key,
        'SQLALCHEMY_DATABASE_URI': app.config['SQLALCHEMY_DATABASE_URI']})
    assert password_grant(restarted.test_client()).json == {'error': 'invalid_grant'}


def test_browser_failure_event_and_bucket_commit_atomically(app, client):
    action = form_action(begin(client).text, 'login-actions/authenticate')
    with app.app_context():
        engine = db.engine
    def reject_audit(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith('INSERT INTO security_events'):
            raise RuntimeError('audit unavailable')
    event.listen(engine, 'before_cursor_execute', reject_audit)
    try:
        response = client.post(action, data={'username': 'demo-user', 'password': 'wrong'})
    finally:
        event.remove(engine, 'before_cursor_execute', reject_audit)
    assert response.status_code == 500
    with app.app_context():
        assert db.session.scalar(select(bucket_model())) is None


def test_postgresql_path_builds_one_atomic_conflict_update():
    from sqlalchemy.dialects import postgresql
    statements = []
    session = SimpleNamespace(get_bind=lambda: SimpleNamespace(dialect=postgresql.dialect()),
                              execute=statements.append)
    throttle = limiter(session, threshold=2)
    throttle.record_failure('realm-id', 'a' * 64, now=NOW)
    assert len(statements) == 1
    compiled = str(statements[0].compile(dialect=postgresql.dialect()))
    assert 'ON CONFLICT (realm_id, bucket_hash) DO UPDATE SET' in compiled
    assert 'login_failure_buckets.failure_count +' in compiled
    assert 'WHERE login_failure_buckets.blocked_until IS NULL OR' in compiled


def test_source_and_realm_buckets_do_not_share_blocks(app, client):
    app.config['LOGIN_FAILURE_THRESHOLD'] = 1
    password_grant(client, password='wrong')
    assert password_grant(client).status_code == 400
    data = dict(grant_type='password', client_id='demo-app', username='demo-user', password='DemoPassw0rd!')
    assert client.post(TOKEN, data=data, environ_overrides={'REMOTE_ADDR': '127.0.0.2'}).status_code == 200
    with app.app_context():
        identities = IdentityRepository(db.session)
        realm = identities.create_realm('other')
        realm.password_grant_enabled = True
        identities.create_client(realm.id, 'demo-app', redirect_uris=[], direct_access_grants_enabled=True)
        db.session.commit()
    other_response = client.post(TOKEN.replace('/demo/', '/other/'), data=data)
    assert other_response.json == {'error': 'invalid_grant'}
    with app.app_context():
        rows = db.session.scalars(select(bucket_model())).all()
        assert len(rows) == 2
        assert len({row.realm_id for row in rows}) == 2
