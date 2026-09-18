from pathlib import Path
import subprocess
import sys
import pytest

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, select, text

from mini_keycloak.extensions import db


@pytest.mark.parametrize('completed_note', [False, True])
def test_flow_revision_preserves_rows_translates_sessions_and_reverses(tmp_path, completed_note):
    url = f"sqlite+pysqlite:///{tmp_path / 'flow-migration.sqlite3'}"
    env = {**__import__('os').environ, 'MINI_KEYCLOAK_DATABASE_URL': url}
    project = Path(__file__).parents[1]

    def migrate(direction, revision):
        subprocess.run([sys.executable, '-m', 'flask', '--app', 'mini_keycloak.app', 'db',
                        direction, revision], cwd=project, env=env, check=True,
                       capture_output=True, text=True)

    engine = create_engine(url)
    try:
        assert_flow_revision_round_trip(engine, migrate, completed_note=completed_note)
    finally:
        engine.dispose()


def assert_flow_revision_round_trip(engine, migrate, *, completed_note=False):
    from uuid import UUID
    from sqlalchemy import MetaData

    migrate('upgrade', '0006')
    original = MetaData()
    original.reflect(engine)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        for realm_id in ('r1', 'r2'):
            connection.execute(original.tables['realms'].insert().values(
                id=realm_id, name=realm_id, name_normalized=realm_id, enabled=True,
                forgot_password_allowed=True, password_grant_enabled=False,
                password_policy={'operator': 'retained'}, created_at=now))
        connection.execute(original.tables['clients'].insert().values(
            id='c', realm_id='r1', client_id='browser', client_id_normalized='browser', enabled=True,
            public_client=True, redirect_uris=[], web_origins=[], standard_flow_enabled=True,
            direct_access_grants_enabled=False, pkce_policy='S256', default_scopes=[], optional_scopes=[],
            post_logout_redirect_uris=[]))
        connection.execute(original.tables['users'].insert().values(
            id='u', realm_id='r1', username='retained', username_normalized='retained',
            enabled=True, email_verified=False, created_at=now))
        for semantic in ('choose-user', 'email-gate', 'update-password', 'authenticated'):
            connection.execute(original.tables['authentication_sessions'].insert().values(
                tab_id=semantic, realm_id='r1', client_id='c', redirect_uri='https://example.test/cb',
                response_type='code', scope='openid', current_execution=semantic,
                selected_user_id='u' if semantic in {'email-gate', 'update-password'} else None,
                auth_notes={'operator': 'retained'}, password_update_allowed=semantic == 'update-password',
                version=4, created_at=now, expires_at=now + timedelta(minutes=5)))
        connection.execute(original.tables['reset_emails'].insert().values(
            id='message', realm_id='r1', user_id='u', recipient='retained@example.test',
            action_token_hash='a' * 64, consumed=True, created_at=now,
            expires_at=now + timedelta(minutes=5)))

    def snapshot():
        with engine.connect() as connection:
            return {name: connection.execute(select(table).order_by(*table.primary_key)).all()
                    for name, table in original.tables.items() if name != 'alembic_version'}

    before = snapshot()
    migrate('upgrade', 'head')
    inspector = inspect(engine)
    assert {'authentication_flows', 'authentication_executions'} <= set(inspector.get_table_names())
    assert {'client_id', 'authentication_session_id', 'token_id', 'action_token', 'consumed_at'} <= {
        column['name'] for column in inspector.get_columns('reset_emails')}
    assert {'flow_id', 'execution_status'} <= {
        column['name'] for column in inspector.get_columns('authentication_sessions')}
    upgraded = MetaData()
    upgraded.reflect(engine)
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT version_num FROM alembic_version')) == '0007'
        assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []
        realms = connection.execute(select(upgraded.tables['realms'])).mappings().all()
        assert len({row['reset_credentials_flow_id'] for row in realms}) == 2
        for realm in realms:
            flow = connection.execute(select(upgraded.tables['authentication_flows']).where(
                upgraded.tables['authentication_flows'].c.id == realm['reset_credentials_flow_id']
            )).mappings().one()
            assert str(UUID(flow['id'])) == flow['id']
            assert flow['realm_id'] == realm['id']
            assert (flow['alias'], flow['provider_id'], flow['built_in']) == (
                'reset credentials', 'basic-flow', True)
            executions = connection.execute(select(upgraded.tables['authentication_executions']).where(
                upgraded.tables['authentication_executions'].c.flow_id == realm['reset_credentials_flow_id']
            ).order_by(upgraded.tables['authentication_executions'].c.priority)).mappings().all()
            assert [row['authenticator'] for row in executions] == [
                'reset-credentials-choose-user', 'reset-credential-email', 'reset-password']
            assert all(row['requirement'] == 'REQUIRED' for row in executions)
            assert [row['priority'] for row in executions] == [10, 20, 30]
            assert len({str(UUID(row['id'])) for row in executions}) == 3
            if realm['id'] == 'r1':
                execution_ids = [row['id'] for row in executions]
        for index, semantic in enumerate(('choose-user', 'email-gate', 'update-password')):
            target_index = min(index, 1)
            session = connection.execute(select(upgraded.tables['authentication_sessions']).where(
                upgraded.tables['authentication_sessions'].c.tab_id == semantic)).mappings().one()
            assert session['flow_id'] is not None
            assert session['current_execution'] == execution_ids[target_index]
            assert session['auth_notes'] == {'operator': 'retained',
                'current.authentication.execution': execution_ids[target_index]}
            assert session['execution_status'] == {**{identifier: 'SUCCESS' for identifier in execution_ids[:target_index]},
                                                  execution_ids[target_index]: 'CHALLENGED'}
            assert session['password_update_allowed'] is False
            assert session['version'] == 4
        assert connection.scalar(text("SELECT current_execution FROM authentication_sessions WHERE tab_id='authenticated'")) == 'authenticated'
        message = connection.execute(select(upgraded.tables['reset_emails'])).mappings().one()
        assert all(message[key] is None for key in (
            'client_id', 'authentication_session_id', 'token_id', 'action_token', 'consumed_at'))
    retained = snapshot()
    for name in before.keys() - {'authentication_sessions'}:
        assert retained[name] == before[name]
    if completed_note:
        with engine.begin() as connection:
            connection.execute(upgraded.tables['authentication_sessions'].update().where(
                upgraded.tables['authentication_sessions'].c.tab_id == 'authenticated').values(
                    auth_notes={'operator': 'retained', 'current.authentication.execution': execution_ids[0]}))
    migrate('downgrade', '0006')
    downgraded = snapshot()
    for name in before.keys() - {'authentication_sessions'}:
        assert downgraded[name] == before[name]
    expected_sessions = {row.tab_id: dict(row._mapping) for row in before['authentication_sessions']}
    # A pending password update needs new delivery after the lifecycle transition.
    expected_sessions['update-password'].update(current_execution='email-gate', password_update_allowed=False)
    assert {row.tab_id: dict(row._mapping) for row in downgraded['authentication_sessions']} == expected_sessions
    assert set(inspect(engine).get_table_names()) == set(original.tables)
    for name, table in original.tables.items():
        assert {column['name'] for column in inspect(engine).get_columns(name)} == set(table.c.keys())
    migrate('upgrade', 'head')
    with engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []


@pytest.mark.parametrize('selected', [False, True])
def test_upgraded_password_session_resumes_message_and_token_continuation(tmp_path, monkeypatch, selected):
    from flask_migrate import downgrade, upgrade
    from mini_keycloak.app import create_app

    monkeypatch.setattr('logging.config.fileConfig', lambda *args, **kwargs: None)
    application = create_app({'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': f"sqlite:///{tmp_path / 'resume-migration.sqlite3'}"})
    migrations = str(Path(__file__).parents[1] / 'migrations')

    def migrate(direction, revision):
        (upgrade if direction == 'upgrade' else downgrade)(directory=migrations, revision=revision)

    try:
        assert_legacy_password_session_resumes(application, migrate, selected=selected)
    finally:
        with application.app_context():
            db.session.remove()
            db.engine.dispose()


def assert_legacy_password_session_resumes(application, migrate, *, selected):
    from datetime import timedelta
    from mini_keycloak.authentication import AuthenticationProcessor, AuthenticatorRegistry
    from mini_keycloak.authentication.constants import CURRENT_AUTHENTICATION_EXECUTION
    from mini_keycloak.models import AuthenticationSession, Client, ResetEmail, User
    from mini_keycloak.models.identity import utc_now
    from mini_keycloak.repositories.identity import IdentityRepository
    from mini_keycloak.reset_credentials.authenticators import (
        ACTION_TOKEN_USER_ID, ResetCredentialChooseUser, ResetCredentialEmail, ResetPassword,
    )
    from mini_keycloak.services.action_tokens import ResetActionTokenService
    from mini_keycloak.services.authentication_flows import AuthenticationFlowService
    from mini_keycloak.services.bootstrap import ensure_demo_realm

    with application.app_context():
        migrate('upgrade', 'head')
        realm = ensure_demo_realm(db.session)
        client = db.session.scalar(select(Client).where(Client.realm_id == realm.id))
        user = db.session.scalar(select(User).where(User.realm_id == realm.id))
        oidc = dict(redirect_uri=client.redirect_uris[0], response_type='code', scope='openid',
                    state='retained-state', nonce='retained-nonce')
        auth = AuthenticationSession(tab_id='retained-password', realm_id=realm.id,
            client_id=client.id, selected_user_id=user.id if selected else None,
            current_execution='update-password', password_update_allowed=True,
            auth_notes={'operator': 'retained', 'auth.selector.screen.rendered': 'true'},
            expires_at=utc_now() + timedelta(minutes=5), **oidc)
        db.session.add(auth)
        db.session.add(ResetEmail(realm_id=realm.id, user_id=user.id, recipient=user.email,
            action_token_hash='d' * 64, consumed=True, expires_at=utc_now() + timedelta(minutes=5)))
        db.session.commit()
        db.session.remove()
        migrate('downgrade', '0006')
        with db.engine.connect() as connection:
            assert connection.scalar(text("SELECT current_execution FROM authentication_sessions")) == 'update-password'
        migrate('upgrade', 'head')
        auth = db.session.get(AuthenticationSession, 'retained-password')
        executions = {item.authenticator: item.id for item in
                      AuthenticationFlowService(db.session).executions(auth.flow_id)}
        processor = AuthenticationProcessor(db.session, realm_name='demo', client_id='demo-app',
            tab_id=auth.tab_id, registry=AuthenticatorRegistry({
                'reset-credentials-choose-user': ResetCredentialChooseUser(),
                'reset-credential-email': ResetCredentialEmail(), 'reset-password': ResetPassword(),
            }))
        outcome = processor.process_flow()
        if not selected:
            assert outcome.page == 'account'
            outcome = processor.process_action(outcome.execution_id, {'username': 'demo-user'})
        assert outcome.page == 'login'
        assert outcome.execution_id == executions['reset-credential-email']
        assert auth.execution_status == {
            executions['reset-credentials-choose-user']: 'SUCCESS', executions['reset-credential-email']: 'FORK'}
        assert ACTION_TOKEN_USER_ID not in auth.auth_notes
        assert not auth.password_update_allowed
        for name, value in oidc.items():
            assert getattr(auth, name) == value
        assert auth.auth_notes['operator'] == 'retained'
        db.session.commit()
        historical = db.session.scalar(select(ResetEmail).where(ResetEmail.authentication_session_id.is_(None)))
        assert historical.consumed and historical.action_token is None
        message = db.session.scalar(select(ResetEmail).where(ResetEmail.authentication_session_id == auth.tab_id))
        assert message is not None and not message.consumed
        continued, user = ResetActionTokenService(db.session).consume('demo', message.action_token)
        assert continued.tab_id == auth.tab_id and user.id == auth.selected_user_id
        auth.auth_notes[ACTION_TOKEN_USER_ID] = user.id
        outcome = processor.process_flow()
        assert outcome.page == 'password' and outcome.execution_id == executions['reset-password']
        assert auth.auth_notes[CURRENT_AUTHENTICATION_EXECUTION] == outcome.execution_id
        assert processor.process_action(outcome.execution_id, {
            'password-new': 'Replacement-password-456!', 'password-confirm': 'Replacement-password-456!'}).complete
        db.session.commit()
        assert IdentityRepository(db.session).password_matches(user, 'Replacement-password-456!')
        assert set(auth.execution_status.values()) == {'SUCCESS'}


def test_upgrade_and_downgrade_empty_database(tmp_path):
    database = tmp_path / "migration.sqlite3"
    env = {
        "MINI_KEYCLOAK_DATABASE_URL": f"sqlite+pysqlite:///{database}",
        "MINI_KEYCLOAK_SECRET_KEY": "migration-test-secret",
    }
    project = Path(__file__).parents[1]
    subprocess.run(
        [sys.executable, "-m", "flask", "--app", "mini_keycloak.app", "db", "upgrade"],
        cwd=project,
        env={**__import__("os").environ, **env},
        check=True,
    )
    inspector = inspect(create_engine(env["MINI_KEYCLOAK_DATABASE_URL"]))
    assert {
        "realms",
        "clients",
        "users",
        "credentials",
        "authentication_sessions",
        "reset_emails",
    } <= set(inspector.get_table_names())
    authentication_session_columns = {
        column["name"]: column
        for column in inspector.get_columns("authentication_sessions")
    }
    assert authentication_session_columns["version"]["nullable"] is False

    subprocess.run(
        [
            sys.executable,
            "-m",
            "flask",
            "--app",
            "mini_keycloak.app",
            "db",
            "downgrade",
            "base",
        ],
        cwd=project,
        env={**__import__("os").environ, **env},
        check=True,
    )
    inspector = inspect(create_engine(env["MINI_KEYCLOAK_DATABASE_URL"]))
    assert "realms" not in inspector.get_table_names()


def test_oidc_revision_preserves_existing_identity_and_downgrades_to_0001(tmp_path):
    database = tmp_path / "oidc-migration.sqlite3"
    url = f"sqlite+pysqlite:///{database}"
    env = {**__import__("os").environ, "MINI_KEYCLOAK_DATABASE_URL": url}
    project = Path(__file__).parents[1]

    def migrate(direction, revision):
        subprocess.run(
            [sys.executable, "-m", "flask", "--app", "mini_keycloak.app", "db", direction, revision],
            cwd=project, env=env, check=True, capture_output=True, text=True,
        )

    migrate("upgrade", "0001")
    engine = create_engine(url)
    original = inspect(engine)
    original_tables = set(original.get_table_names())
    original_columns = {table: {column["name"] for column in original.get_columns(table)}
                        for table in original_tables}
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO realms (id, name, enabled, forgot_password_allowed, password_policy, created_at) VALUES ('r', 'existing', 1, 1, '{}', CURRENT_TIMESTAMP)"))
        connection.execute(text("INSERT INTO clients (id, realm_id, client_id, enabled, public_client, redirect_uris, web_origins, standard_flow_enabled, direct_access_grants_enabled) VALUES ('c', 'r', 'existing-client', 1, 1, '[]', '[]', 1, 0)"))
    migrate("upgrade", "head")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0007"
        assert connection.scalar(text("SELECT password_grant_enabled FROM realms")) == 0
        assert connection.execute(text("SELECT name, enabled, forgot_password_allowed FROM realms")).one() == ("existing", 1, 1)
        assert connection.execute(text("SELECT client_id, direct_access_grants_enabled, pkce_policy FROM clients")).one() == ("existing-client", 0, "S256")
    upgraded = inspect(engine)
    with engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []
    assert {"user_sessions", "authorization_codes", "refresh_tokens", "realm_keys", "security_events"} <= set(upgraded.get_table_names())
    assert {"issuer_override", "access_token_lifetime_seconds", "authorization_code_lifetime_seconds", "refresh_token_lifetime_seconds", "sso_idle_lifetime_seconds", "sso_max_lifetime_seconds"} <= {column["name"] for column in upgraded.get_columns("realms")}
    migrate("downgrade", "0001")
    downgraded = inspect(engine)
    assert set(downgraded.get_table_names()) == original_tables
    for table, columns in original_columns.items():
        assert {column["name"] for column in downgraded.get_columns(table)} == columns
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0001"
        assert connection.scalar(text("SELECT name FROM realms")) == "existing"
        assert connection.scalar(text("SELECT client_id FROM clients")) == "existing-client"
    engine.dispose()


@pytest.mark.parametrize('direction', ['upgrade', 'downgrade'])
def test_throttle_revision_write_failure_rolls_back_schema_and_retries(tmp_path, monkeypatch, direction):
    from flask_migrate import downgrade, upgrade
    from sqlalchemy.exc import IntegrityError
    from mini_keycloak.app import create_app
    from mini_keycloak.models import Realm
    from mini_keycloak.models.identity import utc_now
    from mini_keycloak.security.login_throttling import LoginThrottle
    from mini_keycloak.services.bootstrap import ensure_demo_realm

    monkeypatch.setattr('logging.config.fileConfig', lambda *args, **kwargs: None)
    application = create_app({'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': f"sqlite:///{tmp_path / 'throttle-rollback.sqlite3'}"})
    migrations = str(Path(__file__).parents[1] / 'migrations')
    with application.app_context():
        upgrade(directory=migrations, revision='head')
        ensure_demo_realm(db.session)
        if direction == 'downgrade':
            realm_id = db.session.scalar(select(Realm.id))
            LoginThrottle.from_config(db.session, application.config).record_failure(realm_id, 'a' * 64, now=utc_now())
        db.session.commit()
        db.session.remove()
        downgrade(directory=migrations, revision='0005' if direction == 'upgrade' else '0006')
        with db.engine.begin() as connection:
            connection.exec_driver_sql("""CREATE TRIGGER reject_throttle_revision
                BEFORE UPDATE ON alembic_version
                BEGIN SELECT RAISE(ABORT, 'revision write rejected'); END""")
        def snapshot():
            with db.engine.connect() as connection:
                return (connection.exec_driver_sql('SELECT * FROM sqlite_schema ORDER BY name').all(),
                    {table: connection.execute(text('SELECT * FROM "' + table + '"')).all()
                     for table in inspect(db.engine).get_table_names()})
        before = snapshot()
        migrate, target = (upgrade, '0006') if direction == 'upgrade' else (downgrade, '0005')
        with pytest.raises(IntegrityError, match='revision write rejected'):
            migrate(directory=migrations, revision=target)
        assert snapshot() == before
        with db.engine.begin() as connection:
            connection.exec_driver_sql('DROP TRIGGER reject_throttle_revision')
        migrate(directory=migrations, revision=target)
        with db.engine.connect() as connection:
            assert connection.scalar(text('SELECT version_num FROM alembic_version')) == target


def test_throttle_revision_preserves_all_existing_tables_and_rows(tmp_path):
    from mini_keycloak.models import AuthenticationSession, AuthorizationCode, ResetEmail, User, Realm, Client, RefreshToken, SecurityEvent
    from mini_keycloak.models.identity import utc_now
    from mini_keycloak.services.bootstrap import ensure_demo_realm
    from mini_keycloak.services.sessions import UserSessionService
    from datetime import timedelta
    from mini_keycloak.app import create_app

    url = f"sqlite+pysqlite:///{tmp_path / 'throttle-migration.sqlite3'}"
    env = {**__import__('os').environ, 'MINI_KEYCLOAK_DATABASE_URL': url}
    project = Path(__file__).parents[1]
    def migrate(direction, revision):
        subprocess.run([sys.executable, '-m', 'flask', '--app', 'mini_keycloak.app', 'db',
                        direction, revision], cwd=project, env=env, check=True, capture_output=True)

    migrate('upgrade', 'head')
    application = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': url})
    with application.app_context():
        ensure_demo_realm(db.session)
        realm = db.session.scalar(select(Realm))
        user = db.session.scalar(select(User))
        client = db.session.scalar(select(Client))
        client_id = client.id
        user_session = UserSessionService(db.session, idle_seconds=300, max_seconds=600).create(realm, client, user)
        common = dict(realm_id=realm.id, client_id=client.id, user_id=user.id,
                      user_session_id=user_session.id)
        db.session.add(AuthorizationCode(**common, code_hash='b' * 64,
            redirect_uri='https://example.test/cb', scope='openid', expires_at=utc_now() + timedelta(minutes=5)))
        db.session.add(RefreshToken(**common, token_hash='c' * 64, family_id='retained-family',
            scope='openid', expires_at=utc_now() + timedelta(minutes=5)))
        db.session.add(SecurityEvent(**common, event_type='LOGIN'))
        db.session.add(AuthenticationSession(tab_id='retained-auth', realm_id=realm.id,
            client_id=client_id, selected_user_id=user.id, current_execution='choose-user',
            redirect_uri='https://example.test/cb', expires_at=utc_now() + timedelta(minutes=5)))
        db.session.add(ResetEmail(realm_id=realm.id, user_id=user.id, recipient='test@example.test',
            action_token_hash='a' * 64, expires_at=utc_now() + timedelta(minutes=5)))
        db.session.commit()
        db.session.remove()
        migrate('downgrade', '0005')
        # 0006 may only create its own table, without rewriting retained state.
        def snapshot():
            with db.engine.connect() as connection:
                return {table: connection.execute(text('SELECT * FROM "' + table + '"')).all()
                    for table in inspect(db.engine).get_table_names()
                    if table not in {'alembic_version', 'login_failure_buckets'}}
        before = snapshot()
        assert all(before.values()), 'Every pre-existing table must contain retained data'
        migrate('upgrade', '0006')
        assert 'login_failure_buckets' in inspect(db.engine).get_table_names()
        assert snapshot() == before
        migrate('downgrade', '0005')
        assert 'login_failure_buckets' not in inspect(db.engine).get_table_names()
        assert snapshot() == before
        migrate('upgrade', '0006')
        assert snapshot() == before


def test_import_revision_preserves_existing_users_and_downgrades_to_0003(tmp_path):
    url = f"sqlite+pysqlite:///{tmp_path / 'import-migration.sqlite3'}"
    env = {**__import__("os").environ, "MINI_KEYCLOAK_DATABASE_URL": url}
    project = Path(__file__).parents[1]

    def migrate(direction, revision):
        subprocess.run(
            [sys.executable, "-m", "flask", "--app", "mini_keycloak.app", "db", direction, revision],
            cwd=project, env=env, check=True, capture_output=True, text=True,
        )

    migrate("upgrade", "0003")
    engine = create_engine(url)
    original_columns = {column["name"] for column in inspect(engine).get_columns("users")}
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO realms (id, name, enabled, forgot_password_allowed, password_grant_enabled, password_policy, created_at) VALUES ('r', 'existing', 1, 1, 0, '{}', CURRENT_TIMESTAMP)"))
        connection.execute(text("INSERT INTO users (id, realm_id, username, username_normalized, enabled, email_verified, created_at) VALUES ('u', 'r', 'Alice', 'alice', 1, 0, CURRENT_TIMESTAMP)"))
    migrate("upgrade", "head")
    with engine.connect() as connection:
        assert connection.execute(text("SELECT username, first_name, last_name, attributes FROM users")).one() == ("Alice", None, None, "{}")
        assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []
    migrate("downgrade", "0003")
    assert {column["name"] for column in inspect(engine).get_columns("users")} == original_columns
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT username FROM users")) == "Alice"
    engine.dispose()
