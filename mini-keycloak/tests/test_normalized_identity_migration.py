from contextlib import contextmanager
import importlib.util
from pathlib import Path
import sqlite3

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from flask_migrate import downgrade, upgrade
import pytest
import sqlalchemy as sa

from mini_keycloak.app import create_app
from mini_keycloak.extensions import db


MIGRATIONS = Path(__file__).parents[1] / "migrations"


@pytest.fixture(autouse=True)
def preserve_pytest_logging(monkeypatch):
    # These migrations run in-process to exercise failure injection. Alembic's
    # CLI logging setup would disable already-created application loggers and
    # replace pytest's handlers, leaking state into later ordinary logging tests.
    # Keep only that process-wide setup out of the database migration tests.
    monkeypatch.setattr("logging.config.fileConfig", lambda *args, **kwargs: None)


@contextmanager
def legacy_database(tmp_path, foreign_keys=1):
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'legacy.sqlite3'}"})
    with app.app_context():
        upgrade(directory=str(MIGRATIONS), revision="0004")
        with db.engine.begin() as connection:
            connection.execute(sa.text("INSERT INTO realms (id, name, enabled, forgot_password_allowed, password_grant_enabled, password_policy, created_at) VALUES ('r', '  Straße  ', 1, 1, 0, '{}', CURRENT_TIMESTAMP), ('r2', 'Other', 1, 1, 0, '{}', CURRENT_TIMESTAMP)"))
            connection.execute(sa.text("INSERT INTO clients (id, realm_id, client_id, enabled, public_client, redirect_uris, web_origins, standard_flow_enabled, direct_access_grants_enabled) VALUES ('c', 'r', '  Straße-ﬃ  ', 1, 1, '[]', '[]', 1, 0), ('c2', 'r2', 'STRASSE-FFI', 1, 1, '[]', '[]', 1, 0)"))
            connection.execute(sa.text("INSERT INTO users (id, realm_id, username, username_normalized, enabled, email_verified, created_at) VALUES ('u', 'r', 'Alice', 'alice', 1, 0, CURRENT_TIMESTAMP)"))
            connection.execute(sa.text("INSERT INTO credentials (id, user_id, type, secret_hash, created_at) VALUES ('password', 'u', 'password', 'preserved-hash', CURRENT_TIMESTAMP)"))
            connection.execute(sa.text("INSERT INTO user_sessions (id, realm_id, client_id, user_id, sid, auth_time, created_at, last_refresh_at, idle_expires_at, max_expires_at) VALUES ('s', 'r', 'c', 'u', 'preserved-sid', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
            connection.execute(sa.text("INSERT INTO realm_keys (id, realm_id, kid, algorithm, encrypted_private_pem, public_jwk, active, created_at, activated_at) VALUES ('key', 'r', 'preserved-kid', 'RS256', 'preserved-encrypted-key', '{}', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
        with db.engine.connect() as connection:
            connection.exec_driver_sql(f"PRAGMA foreign_keys={foreign_keys}")
        try:
            yield db.engine
        finally:
            db.session.remove()
            db.engine.dispose()


def snapshot(engine):
    metadata = sa.MetaData()
    metadata.reflect(bind=engine)
    with engine.connect() as connection:
        return {table.name: [dict(row) for row in connection.execute(sa.select(table).order_by(*table.primary_key.columns)).mappings()]
                for table in metadata.sorted_tables}


def schema_snapshot(engine):
    with engine.connect() as connection:
        return connection.exec_driver_sql(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name"
        ).all()


@pytest.mark.parametrize("foreign_keys", [0, 1])
def test_0005_backfills_casefold_preserves_all_rows_and_round_trips(tmp_path, foreign_keys):
    with legacy_database(tmp_path, foreign_keys) as engine:
        original = snapshot(engine)
        upgrade(directory=str(MIGRATIONS), revision="head")
        inspector = sa.inspect(engine)
        for table, column in (("realms", "name_normalized"), ("clients", "client_id_normalized")):
            columns = {item["name"]: item for item in inspector.get_columns(table)}
            assert column in columns
            assert columns[column]["nullable"] is False
            assert columns[column]["default"] is None
        with engine.connect() as connection:
            assert connection.execute(sa.text("SELECT name, name_normalized FROM realms WHERE id='r'")).one() == ("  Straße  ", "strasse")
            assert connection.execute(sa.text("SELECT client_id, client_id_normalized FROM clients WHERE id='c'")).one() == ("  Straße-ﬃ  ", "strasse-ffi")
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == foreign_keys
            assert connection.exec_driver_sql("PRAGMA defer_foreign_keys").scalar() == 0
            assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []
        current = snapshot(engine)
        for table, rows in original.items():
            if table == "alembic_version":
                continue
            assert [{key: value for key, value in row.items() if key not in {"name_normalized", "client_id_normalized"}}
                    for row in current[table]] == rows
        # Constraint enforcement is exercised on the migrated database, not only create_all.
        for statement in (
            "UPDATE realms SET name_normalized='strasse' WHERE id='r2'",
            "UPDATE clients SET realm_id='r' WHERE id='c2'",
            "UPDATE realms SET name_normalized=NULL WHERE id='r'",
            "UPDATE clients SET client_id_normalized=NULL WHERE id='c'",
        ):
            with pytest.raises(sa.exc.IntegrityError), engine.begin() as connection:
                connection.execute(sa.text(statement))
        downgrade(directory=str(MIGRATIONS), revision="0004")
        assert snapshot(engine) == original
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == foreign_keys
            assert connection.exec_driver_sql("PRAGMA defer_foreign_keys").scalar() == 0
        upgrade(directory=str(MIGRATIONS), revision="head")
        with engine.connect() as connection:
            assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []


@pytest.mark.parametrize("foreign_keys", [0, 1])
@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_0005_revision_write_failure_rolls_back_schema_rows_and_retries(tmp_path, direction, foreign_keys):
    with legacy_database(tmp_path, foreign_keys) as engine:
        if direction == "downgrade":
            upgrade(directory=str(MIGRATIONS), revision="0005")
        migrate, target = (upgrade, "0005") if direction == "upgrade" else (downgrade, "0004")
        with engine.begin() as connection:
            # Fail the real Alembic version UPDATE in SQLite, after the revision
            # has finished all schema work. No database operation is mocked.
            connection.exec_driver_sql("""
                CREATE TRIGGER reject_revision_write BEFORE UPDATE ON alembic_version
                BEGIN SELECT RAISE(ABORT, 'injected revision write failure'); END
            """)
            migration_connection = connection.connection.driver_connection
        original = snapshot(engine)
        original_schema = schema_snapshot(engine)

        with pytest.raises(sa.exc.IntegrityError, match="injected revision write failure"):
            migrate(directory=str(MIGRATIONS), revision=target)

        assert schema_snapshot(engine) == original_schema
        assert snapshot(engine) == original
        assert migration_connection.execute("PRAGMA foreign_keys").fetchone() == (foreign_keys,)
        assert migration_connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert migration_connection.execute("PRAGMA defer_foreign_keys").fetchone() == (0,)
        assert not migration_connection.in_transaction

        with engine.begin() as connection:
            connection.exec_driver_sql("DROP TRIGGER reject_revision_write")
        migrate(directory=str(MIGRATIONS), revision=target)
        current = snapshot(engine)
        assert current["alembic_version"] == [{"version_num": target}]
        for table, column in (("realms", "name_normalized"), ("clients", "client_id_normalized")):
            assert (column in {item["name"] for item in sa.inspect(engine).get_columns(table)}) == (target == "0005")
        for table, rows in original.items():
            if table != "alembic_version":
                assert [{key: value for key, value in row.items()
                         if key not in {"name_normalized", "client_id_normalized"}} for row in current[table]] == [
                    {key: value for key, value in row.items()
                     if key not in {"name_normalized", "client_id_normalized"}} for row in rows]
        assert migration_connection.execute("PRAGMA foreign_keys").fetchone() == (foreign_keys,)
        assert migration_connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize("foreign_keys", [0, 1])
@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_0005_holds_writer_lock_through_revision_write(tmp_path, direction, foreign_keys):
    with legacy_database(tmp_path, foreign_keys) as engine:
        if direction == "downgrade":
            upgrade(directory=str(MIGRATIONS), revision="0005")
        migrate, target = (upgrade, "0005") if direction == "upgrade" else (downgrade, "0004")
        competitor = sqlite3.connect(str(engine.url.database), timeout=0)
        observations = []

        def attempt_writer(stage):
            try:
                competitor.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                assert str(error) == "database is locked"
                observations.append((stage, "blocked"))
            else:
                observations.append((stage, "acquired"))
                competitor.rollback()

        def before_statement(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith("UPDATE alembic_version"):
                attempt_writer("before revision write")

        def after_statement(connection, cursor, statement, parameters, context, executemany):
            if statement == "PRAGMA foreign_key_check":
                attempt_writer("schema complete")
            elif statement.startswith("UPDATE alembic_version"):
                attempt_writer("after revision write")

        sa.event.listen(engine, "before_cursor_execute", before_statement)
        sa.event.listen(engine, "after_cursor_execute", after_statement)
        try:
            migrate(directory=str(MIGRATIONS), revision=target)
            attempt_writer("migration complete")
        finally:
            sa.event.remove(engine, "before_cursor_execute", before_statement)
            sa.event.remove(engine, "after_cursor_execute", after_statement)
            competitor.close()
        assert observations == [
            ("schema complete", "blocked"),
            ("before revision write", "blocked"),
            ("after revision write", "blocked"),
            ("migration complete", "acquired"),
        ]
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == target
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == foreign_keys
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []


@pytest.mark.parametrize("foreign_keys", [0, 1])
@pytest.mark.parametrize("entity", ["realm", "client"])
def test_0005_rejects_legacy_collisions_before_changing_schema_or_data(tmp_path, entity, foreign_keys):
    with legacy_database(tmp_path, foreign_keys) as engine:
        with engine.begin() as connection:
            if entity == "realm":
                connection.execute(sa.text("UPDATE realms SET name='STRASSE' WHERE id='r2'"))
            else:
                connection.execute(sa.text("UPDATE clients SET realm_id='r' WHERE id='c2'"))
        original = snapshot(engine)
        original_columns = {table: sa.inspect(engine).get_columns(table) for table in ("realms", "clients")}
        with pytest.raises(ValueError, match="Normalized identity collision") as error:
            upgrade(directory=str(MIGRATIONS), revision="head")
        assert "Straße" not in str(error.value) and "STRASSE" not in str(error.value)
        assert snapshot(engine) == original
        for table, columns in original_columns.items():
            assert [column["name"] for column in sa.inspect(engine).get_columns(table)] == [column["name"] for column in columns]
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == foreign_keys
            assert connection.exec_driver_sql("PRAGMA defer_foreign_keys").scalar() == 0


@pytest.mark.parametrize("foreign_keys", [0, 1])
@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
@pytest.mark.parametrize("stage", ["begin", "rebuild", "integrity"])
def test_0005_failure_restores_schema_rows_and_foreign_key_enforcement(tmp_path, stage, direction, foreign_keys):
    with legacy_database(tmp_path, foreign_keys) as engine:
        if direction == "downgrade":
            upgrade(directory=str(MIGRATIONS), revision="0005")
        migrate, target = (upgrade, "0005") if direction == "upgrade" else (downgrade, "0004")
        original = snapshot(engine)
        original_schema = schema_snapshot(engine)
        final_table = "clients" if direction == "upgrade" else "realms"

        def fail_migration(connection, cursor, statement, parameters, context, executemany):
            if ((stage == "begin" and statement == "BEGIN IMMEDIATE")
                    or (stage == "rebuild" and f"CREATE TABLE _alembic_tmp_{final_table}" in statement)):
                raise ValueError("injected migration failure")
            if stage == "integrity" and statement == "PRAGMA foreign_key_check":
                connection.exec_driver_sql("UPDATE users SET realm_id='missing-realm' WHERE id='u'")

        sa.event.listen(engine, "before_cursor_execute", fail_migration)
        try:
            message = "Foreign key integrity check failed" if stage == "integrity" else "injected migration failure"
            with pytest.raises(ValueError, match=message):
                migrate(directory=str(MIGRATIONS), revision=target)
        finally:
            sa.event.remove(engine, "before_cursor_execute", fail_migration)
        assert snapshot(engine) == original
        assert schema_snapshot(engine) == original_schema
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == foreign_keys
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            assert connection.exec_driver_sql("PRAGMA defer_foreign_keys").scalar() == 0


def load_revision():
    files = list((MIGRATIONS / "versions").glob("0005_*.py"))
    assert len(files) == 1, "The normalized identity revision 0005 must exist"
    spec = importlib.util.spec_from_file_location("normalized_identity_revision", files[0])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0005_postgresql_compiles_matching_orm_constraints_and_backfill(tmp_path, monkeypatch):
    revision = load_revision()
    statements = []
    with legacy_database(tmp_path) as engine, engine.connect() as source:
        def execute(statement, *multiparams, **params):
            statements.append((str(statement.compile(dialect=postgres.dialect)), multiparams, params))
            if isinstance(statement, sa.sql.Select):
                return source.execute(statement)

        postgres = sa.create_mock_engine("postgresql://", execute)
        context = MigrationContext.configure(postgres)
        monkeypatch.setattr(revision, "op", Operations(context))
        revision.upgrade()
        ddl = "\n".join(statement for statement, _, _ in statements)
        for table, column, name, fields in (
            ("realms", "name_normalized", "uq_realms_name_normalized", "name_normalized"),
            ("clients", "client_id_normalized", "uq_clients_realm_client_id_normalized", "realm_id, client_id_normalized"),
        ):
            assert f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR(765)" in ddl
            assert f"ALTER TABLE {table} ALTER COLUMN {column} SET NOT NULL" in ddl
            assert f"ADD CONSTRAINT {name} UNIQUE ({fields})" in ddl
            model_ddl = str(sa.schema.CreateTable(db.metadata.tables[table]).compile(dialect=postgres.dialect))
            assert f"{column} VARCHAR(765) NOT NULL" in model_ddl
            assert f"CONSTRAINT {name} UNIQUE ({fields})" in model_ddl
        assert "strasse" in repr(statements) and "strasse-ffi" in repr(statements)
        statements.clear()
        revision.downgrade()
        ddl = "\n".join(statement for statement, _, _ in statements)
        assert "DROP CONSTRAINT uq_realms_name_normalized" in ddl
        assert "DROP CONSTRAINT uq_clients_realm_client_id_normalized" in ddl
        assert "DROP COLUMN name_normalized" in ddl
        assert "DROP COLUMN client_id_normalized" in ddl
