from datetime import timedelta

import pytest
from sqlalchemy import event, func, select

from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationSession, AuthorizationCode, RefreshToken, SecurityEvent, UserSession
from mini_keycloak.models.identity import utc_now
from tests.test_authorization_code import issue, returned_code
from tests.test_token_endpoint import exchange
from tests.test_client_authentication import TOKEN


def assert_cleanup_retains_linked_outbox(application):
    from mini_keycloak.models import Client, ResetEmail, User
    from mini_keycloak.services.action_tokens import ResetActionTokenService
    from mini_keycloak.services.authentication_flows import AuthenticationFlowService
    from mini_keycloak.services.bootstrap import ensure_demo_realm
    from mini_keycloak.services.cleanup import cleanup_expired
    from mini_keycloak.services.sessions import UserSessionService
    from mini_keycloak.security.login_throttling import LoginThrottle

    with application.app_context():
        realm = ensure_demo_realm(db.session)
        client = db.session.scalar(select(Client).where(Client.realm_id == realm.id))
        user = db.session.scalar(select(User).where(User.realm_id == realm.id))
        flow = AuthenticationFlowService(db.session).ensure_reset_flow(realm)
        execution = AuthenticationFlowService(db.session).executions(flow.id)[0]
        now = utc_now()
        tokens = ResetActionTokenService(db.session)
        for index in range(3):
            auth = AuthenticationSession(tab_id=f'cleanup-reset-{index}', realm_id=realm.id,
                client_id=client.id, selected_user_id=user.id, flow_id=flow.id,
                current_execution=execution.id, redirect_uri=client.redirect_uris[0],
                expires_at=now + timedelta(minutes=5))
            db.session.add(auth)
            db.session.flush()
            message = tokens.issue(auth, user)
            if index == 0:
                tokens.consume(realm.name, message.action_token)
            if index < 2:
                auth.expires_at = now - timedelta(seconds=1)
        user_session = UserSessionService(db.session, idle_seconds=300, max_seconds=600).create(
            realm, client, user)
        user_session.idle_expires_at = now - timedelta(seconds=1)
        common = dict(realm_id=realm.id, client_id=client.id, user_id=user.id,
                      user_session_id=user_session.id)
        db.session.add(AuthorizationCode(**common, code_hash='a' * 64,
            redirect_uri=client.redirect_uris[0], scope='openid', expires_at=now + timedelta(minutes=5)))
        db.session.add(RefreshToken(**common, token_hash='b' * 64, family_id='cleanup-family',
            scope='openid', expires_at=now + timedelta(minutes=5)))
        audit = SecurityEvent(**common, event_type='LOGIN')
        db.session.add(audit)
        LoginThrottle(db.session, secret=application.secret_key, threshold=5,
            window_seconds=300, lock_seconds=60).record_failure(
                realm.id, 'c' * 64, now=now - timedelta(minutes=10))
        db.session.commit()
        audit_id = audit.id
        original = {row.id: dict(row) for row in
                    db.session.execute(select(ResetEmail.__table__)).mappings()}

        def fail_delete(connection, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith('DELETE FROM AUTHENTICATION_SESSIONS'):
                raise RuntimeError('cleanup deletion unavailable')

        event.listen(db.engine, 'before_cursor_execute', fail_delete)
        try:
            with pytest.raises(RuntimeError, match='cleanup deletion unavailable'):
                cleanup_expired(db.session, batch_size=1)
        finally:
            event.remove(db.engine, 'before_cursor_execute', fail_delete)
        assert db.session.scalar(select(func.count()).select_from(AuthenticationSession)) == 3
        for row in db.session.execute(select(ResetEmail.__table__)).mappings():
            unchanged = dict(row) == original[row.id]
            assert unchanged
        assert db.session.scalar(select(func.count()).select_from(UserSession)) == 1
        counts = cleanup_expired(db.session, batch_size=1)
        assert counts == dict(authentication_sessions=2, authorization_codes=1, refresh_tokens=1,
                              user_sessions=1, login_failure_buckets=1)
        db.session.expire_all()
        retained = db.session.execute(select(ResetEmail.__table__)).mappings().all()
        assert len(retained) == 3
        for row in retained:
            before = original[row.id]
            expected_link = 'cleanup-reset-2' if before['authentication_session_id'] == 'cleanup-reset-2' else None
            assert row['authentication_session_id'] == expected_link
            unchanged = all(row[key] == value for key, value in before.items()
                            if key != 'authentication_session_id')
            assert unchanged
        assert db.session.get(SecurityEvent, audit_id).user_session_id is None
        assert list(db.session.scalars(select(AuthenticationSession.tab_id))) == ['cleanup-reset-2']
        assert all(count == 0 for count in cleanup_expired(db.session, batch_size=1).values())


def test_cleanup_retains_consumed_and_pending_outbox_and_continues_batches(app):
    assert_cleanup_retains_linked_outbox(app)


def test_cleanup_batches_expired_dependencies_preserves_live_rows_and_audit(app):
    sessions = []
    for _ in range(3):
        browser = app.test_client()
        tokens = exchange(browser, returned_code(issue(browser))).json
        sessions.append(tokens['session_state'])
    assert browser.post(TOKEN, data=dict(grant_type='refresh_token', client_id='demo-app',
                        refresh_token=tokens['refresh_token'])).status_code == 200
    with app.app_context():
        now = utc_now()
        doomed = db.session.scalars(select(UserSession).where(UserSession.sid.in_(sessions[:2]))).all()
        doomed[0].idle_expires_at = now - timedelta(seconds=1)
        doomed[1].revoked_at = now
        doomed[1].max_expires_at = now - timedelta(seconds=1)
        doomed_ids = [row.id for row in doomed]
        auths = db.session.scalars(select(AuthenticationSession).order_by(AuthenticationSession.created_at)).all()
        for auth in auths[:2]:
            auth.expires_at = now - timedelta(seconds=1)
        live_session = db.session.scalar(select(UserSession).where(UserSession.sid == sessions[2]))
        parent = db.session.scalar(select(RefreshToken).where(
            RefreshToken.user_session_id == live_session.id, RefreshToken.generation == 0))
        parent.expires_at = now - timedelta(seconds=1)
        live_refresh = parent.replaced_by_id
        audit_ids = set(db.session.scalars(select(SecurityEvent.id)))
        db.session.commit()
        tables = (AuthenticationSession, AuthorizationCode, RefreshToken, UserSession)
        def row_count():
            with db.engine.connect() as connection:
                return sum(connection.scalar(select(func.count()).select_from(table)) for table in tables)
        snapshots = [row_count()]
        def committed(session):
            snapshots.append(row_count())
        event.listen(db.session(), 'after_commit', committed)
        try:
            result = app.test_cli_runner().invoke(args=['cleanup-expired', '--batch-size', '1'])
        finally:
            event.remove(db.session(), 'after_commit', committed)
        assert result.exit_code == 0, result.output
        assert 'authentication_sessions=2' in result.output
        assert 'authorization_codes=2' in result.output
        assert 'refresh_tokens=3' in result.output
        assert 'user_sessions=2' in result.output
        assert len(snapshots) >= 10
        assert all(0 <= before - after <= 1 for before, after in zip(snapshots, snapshots[1:]))
        db.session.expire_all()
        assert set(db.session.scalars(select(UserSession.sid))) == {sessions[2]}
        assert set(db.session.scalars(select(RefreshToken.id))) == {live_refresh}
        assert set(db.session.scalars(select(SecurityEvent.id))) == audit_ids
        assert not db.session.scalar(select(SecurityEvent).where(SecurityEvent.user_session_id.in_(doomed_ids)))
        repeated = app.test_cli_runner().invoke(args=['cleanup-expired', '--batch-size', '1'])
        assert repeated.exit_code == 0
        assert repeated.output.strip() == 'authentication_sessions=0 authorization_codes=0 refresh_tokens=0 user_sessions=0 login_failure_buckets=0'


@pytest.mark.parametrize('size', ['0', '-1', '1001', 'abc'])
def test_cleanup_rejects_invalid_batch_size_without_deleting(app, size):
    result = app.test_cli_runner().invoke(args=['cleanup-expired', '--batch-size', size])
    assert result.exit_code == 2
    assert 'batch-size' in result.output


def test_cleanup_unlinks_retained_refresh_references_before_deleting(app, client):
    tokens = exchange(client, returned_code(issue(client))).json
    client.post(TOKEN, data=dict(grant_type='refresh_token', client_id='demo-app',
                                refresh_token=tokens['refresh_token']))
    with app.app_context():
        parent = db.session.scalar(select(RefreshToken).where(RefreshToken.generation == 0))
        child = db.session.scalar(select(RefreshToken).where(RefreshToken.generation == 1))
        child.expires_at = utc_now() - timedelta(seconds=1)
        parent_id = parent.id
        db.session.commit()
    result = app.test_cli_runner().invoke(args=['cleanup-expired', '--batch-size', '1'])
    assert result.exit_code == 0, result.output
    with app.app_context():
        assert db.session.get(RefreshToken, parent_id).replaced_by_id is None
        assert len(db.session.scalars(select(RefreshToken)).all()) == 1


def test_cleanup_batches_only_expired_failure_buckets(app):
    from mini_keycloak.models import LoginFailureBucket, Realm
    from mini_keycloak.security.login_throttling import LoginThrottle
    with app.app_context():
        realm_id = db.session.scalar(select(Realm.id))
        now = utc_now()
        throttle = LoginThrottle(db.session, secret=app.secret_key,
                                 threshold=5, window_seconds=300, lock_seconds=60)
        for index in range(4):
            throttle.record_failure(realm_id, f'{index:064x}',
                now=now - timedelta(seconds=301) if index < 3 else now)
        db.session.commit()
        def count():
            with db.engine.connect() as connection:
                return connection.scalar(select(func.count()).select_from(LoginFailureBucket))
        snapshots = [count()]
        def committed(session):
            snapshots.append(count())
        event.listen(db.session(), 'after_commit', committed)
        try:
            result = app.test_cli_runner().invoke(args=['cleanup-expired', '--batch-size', '1'])
        finally:
            event.remove(db.session(), 'after_commit', committed)
        assert result.exit_code == 0, result.output
        assert 'login_failure_buckets=3' in result.output
        assert snapshots[-1] == 1
        assert all(0 <= before - after <= 1 for before, after in zip(snapshots, snapshots[1:]))
        assert [row.bucket_hash for row in db.session.scalars(select(LoginFailureBucket))] == [f'{3:064x}']


def test_cleanup_preserves_live_sessions_in_another_realm(app, client):
    from mini_keycloak.repositories.identity import IdentityRepository
    from mini_keycloak.services.sessions import UserSessionService
    exchange(client, returned_code(issue(client)))
    with app.app_context():
        db.session.scalar(select(UserSession)).max_expires_at = utc_now() - timedelta(seconds=1)
        identities = IdentityRepository(db.session)
        realm = identities.create_realm('other')
        other_client = identities.create_client(realm.id, 'demo-app', redirect_uris=['https://other.test/cb'])
        user = identities.create_user(realm.id, 'demo-user', None, 'OtherPassw0rd!')
        live = UserSessionService(db.session, idle_seconds=300, max_seconds=600).create(realm, other_client, user)
        live_id = live.id
        db.session.commit()
    result = app.test_cli_runner().invoke(args=['cleanup-expired', '--batch-size', '1'])
    assert result.exit_code == 0, result.output
    with app.app_context():
        assert set(db.session.scalars(select(UserSession.id))) == {live_id}


@pytest.mark.parametrize('expired_hint', [False, True])
@pytest.mark.parametrize('expiration', ['idle_expires_at', 'max_expires_at'])
def test_cleanup_retains_logout_retry_until_session_expiry(app, client, expired_hint, expiration):
    from mini_keycloak.services.cleanup import cleanup_expired
    from tests.test_logout import DESTINATION, LOGOUT, allow_redirect
    from tests.test_refresh_tokens import refresh
    from tests.test_userinfo import USERINFO, bearer, signed_variant

    tokens = exchange(client, returned_code(issue(client))).json
    allow_redirect(app)
    hint = signed_variant(app, tokens['id_token'], exp=1) if expired_hint else tokens['id_token']
    params = {'id_token_hint': hint, 'post_logout_redirect_uri': DESTINATION}
    initial = client.get(LOGOUT, query_string=params)
    assert initial.status_code == 302
    with app.app_context():
        retained = db.session.scalar(select(UserSession))
        session_id, revoked_at = retained.id, retained.revoked_at
        counts = cleanup_expired(db.session, batch_size=1)
        assert counts['user_sessions'] == 0
        assert counts['authorization_codes'] == counts['refresh_tokens'] == 1
        db.session.expire_all()
        assert db.session.get(UserSession, session_id).revoked_at == revoked_at
        assert db.session.scalar(select(SecurityEvent).where(SecurityEvent.user_session_id == session_id))
    repeated = client.get(LOGOUT, query_string=params)
    assert repeated.status_code == 302
    assert repeated.location == initial.location
    assert client.get(USERINFO, headers=bearer(tokens['access_token'])).status_code == 401
    assert refresh(client, tokens['refresh_token']).json == {'error': 'invalid_grant'}
    unknown = signed_variant(app, hint, sid='unknown-session')
    assert client.get(LOGOUT, query_string={'id_token_hint': unknown}).status_code == 401
    with app.app_context():
        retained = db.session.get(UserSession, session_id)
        assert retained.revoked_at == revoked_at
        setattr(retained, expiration, utc_now() - timedelta(seconds=1))
        db.session.commit()
        assert cleanup_expired(db.session, batch_size=1)['user_sessions'] == 1
        db.session.expire_all()
        assert db.session.get(UserSession, session_id) is None
        assert db.session.scalar(select(SecurityEvent).where(SecurityEvent.user_session_id == session_id)) is None
    assert client.get(LOGOUT, query_string=params).status_code == 401
