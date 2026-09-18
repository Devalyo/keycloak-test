from pathlib import Path
import subprocess
import sys
import pytest

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, select, text

from mini_keycloak.extensions import db


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
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0006"
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
        upgrade(directory=migrations, revision='0005' if direction == 'upgrade' else '0006')
        ensure_demo_realm(db.session)
        if direction == 'downgrade':
            realm_id = db.session.scalar(select(Realm.id))
            LoginThrottle.from_config(db.session, application.config).record_failure(realm_id, 'a' * 64, now=utc_now())
        db.session.commit()
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

    migrate('upgrade', '0005')
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
        # 0006 may only create its own table, without rewriting retained state.
        def snapshot():
            with db.engine.connect() as connection:
                return {table: connection.execute(text('SELECT * FROM "' + table + '"')).all()
                    for table in inspect(db.engine).get_table_names()
                    if table not in {'alembic_version', 'login_failure_buckets'}}
        before = snapshot()
        assert all(before.values()), 'Every pre-existing table must contain retained data'
        migrate('upgrade', 'head')
        assert 'login_failure_buckets' in inspect(db.engine).get_table_names()
        assert snapshot() == before
        with db.engine.connect() as connection:
            assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []
        migrate('downgrade', '0005')
        assert 'login_failure_buckets' not in inspect(db.engine).get_table_names()
        assert snapshot() == before
        migrate('upgrade', 'head')
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
