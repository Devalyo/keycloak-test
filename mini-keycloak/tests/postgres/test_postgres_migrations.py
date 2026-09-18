"""Run actual transactional Alembic DDL on PostgreSQL, not SQL compilation."""

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from mini_keycloak.extensions import db
from tests.test_migrations import assert_flow_revision_round_trip, assert_legacy_password_session_resumes
from .conftest import migrate
from .support import seed_graph, snapshot


pytestmark = pytest.mark.postgres


@pytest.mark.parametrize('completed_note', [False, True])
def test_flow_revision_seeds_preserves_translates_and_reverses(postgres_database, completed_note):
    application = postgres_database.app()
    with application.app_context():
        assert_flow_revision_round_trip(db.engine, migrate, completed_note=completed_note)


@pytest.mark.parametrize('selected', [False, True])
def test_upgraded_password_session_resumes_message_and_token_continuation(postgres_database, selected):
    assert_legacy_password_session_resumes(postgres_database.app(), migrate, selected=selected)


def test_empty_database_round_trip_matches_metadata(postgres_database):
    application = postgres_database.app()
    with application.app_context():
        for direction, revision in (("upgrade", "head"), ("downgrade", "base"), ("upgrade", "head")):
            migrate(direction, revision)
            tables = set(inspect(db.engine).get_table_names())
            if revision == "base":
                assert tables == {"alembic_version"}
            else:
                assert tables == set(db.metadata.tables) | {"alembic_version"}
                with db.engine.connect() as connection:
                    assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0007"
                    assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []
                # Alembic comparison covers columns/types/FKs/unique constraints
                # and indexes; primary-key column changes need an explicit check.
                inspector = inspect(db.engine)
                for name, table in db.metadata.tables.items():
                    assert inspector.get_pk_constraint(name)["constrained_columns"] == [column.name for column in table.primary_key]


def test_normalized_backfill_preserves_populated_graph_and_round_trips(postgres_app, postgres_database):
    import hashlib
    import json
    from sqlalchemy import MetaData, select

    with postgres_app.app_context():
        seed_graph(db.session, postgres_database.master)
        db.session.remove()
        migrate("downgrade", "0004")
        original = snapshot(db.engine)
        legacy = MetaData()
        legacy.reflect(bind=db.engine)
        assert all(count for count, digest in original.values()), "Every legacy table must contain rows"
        migrate("upgrade", "head")
        with db.engine.connect() as connection:
            assert connection.execute(text("SELECT name, name_normalized FROM realms")).one() == ("  Straße  ", "strasse")
            assert connection.execute(text("SELECT client_id, client_id_normalized FROM clients")).one() == ("  Straße-ﬃ  ", "strasse-ffi")
            assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []
        # Compare each historical table through its historical column set;
        # later revisions add flow/outbox metadata without replacing its rows.
        with db.engine.connect() as connection:
            for name, table in legacy.tables.items():
                if name == "alembic_version":
                    continue
                rows = connection.execute(select(table).order_by(*table.primary_key.columns)).all()
                payload = json.dumps([list(row) for row in rows], default=str, sort_keys=True)
                assert (len(rows), hashlib.sha256(payload.encode()).hexdigest()) == original[name]
        for table, column in (("realms", "name_normalized"), ("clients", "client_id_normalized")):
            reflected = {item["name"]: item for item in inspect(db.engine).get_columns(table)}
            assert reflected[column]["nullable"] is False
            assert reflected[column]["default"] is None
            with pytest.raises(IntegrityError), db.engine.begin() as connection:
                connection.execute(text(f"UPDATE {table} SET {column}=NULL"))
        migrate("downgrade", "0004")
        assert snapshot(db.engine) == original
        migrate("upgrade", "head")


@pytest.mark.parametrize("entity", ["realm", "client"])
def test_normalized_collision_rolls_back_and_retries(postgres_app, postgres_database, entity, caplog):
    with postgres_app.app_context():
        seed_graph(db.session, postgres_database.master)
        db.session.remove()
        migrate("downgrade", "0004")
        table, column = ("realms", "name") if entity == "realm" else ("clients", "client_id")
        # Copy every old column through the reflected schema, altering only its
        # primary key and raw identity. These casefold collisions are legal at 0004.
        from sqlalchemy import MetaData, Table, select
        legacy = Table(table, MetaData(), autoload_with=db.engine)
        with db.engine.begin() as connection:
            duplicate = dict(connection.execute(select(legacy)).mappings().one())
            duplicate.update(id="collision", **{column: "STRASSE" if entity == "realm" else "STRASSE-FFI"})
            connection.execute(legacy.insert().values(**duplicate))
        before = snapshot(db.engine)
        before_columns = {name: inspect(db.engine).get_columns(name) for name in ("realms", "clients")}
        with pytest.raises(ValueError) as failure:
            migrate("upgrade", "0005")
        assert str(failure.value) == f"Normalized identity collision in {table}; resolve before migration"
        assert snapshot(db.engine) == before
        for name, columns in before_columns.items():
            assert [item["name"] for item in inspect(db.engine).get_columns(name)] == [item["name"] for item in columns]
        # If rollback retains the exclusive lock this independent correction
        # times out; the retry must apply the whole migration normally.
        with db.engine.begin() as connection:
            connection.execute(legacy.update().where(legacy.c.id == "collision").values(**{column: "Resolved"}))
        migrate("upgrade", "head")
        with db.engine.connect() as connection:
            assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []
        assert not any(value in caplog.text for value in (postgres_database.url, postgres_database.master))


def test_throttle_revision_preserves_all_other_rows(postgres_app, postgres_database):
    with postgres_app.app_context():
        seed_graph(db.session, postgres_database.master)
        db.session.remove()
        migrate("downgrade", "0006")
        original = snapshot(db.engine)
        assert all(count for count, digest in original.values()), "Every table must contain retained data"
        migrate("upgrade", "0006")
        assert snapshot(db.engine) == original
        retained = {table: value for table, value in original.items()
                    if table not in {"alembic_version", "login_failure_buckets"}}
        for direction, revision in (("downgrade", "0005"), ("upgrade", "0006"), ("downgrade", "0005"), ("upgrade", "0006")):
            migrate(direction, revision)
            assert snapshot(db.engine, omit_tables={"alembic_version", "login_failure_buckets"}) == retained
        migrate("upgrade", "head")
        with db.engine.connect() as connection:
            assert compare_metadata(MigrationContext.configure(connection), db.metadata) == []


@pytest.mark.parametrize("revision, previous", [("0005", "0004"), ("0006", "0005"), ("0007", "0006")])
@pytest.mark.parametrize("direction", ["upgrade", "downgrade"])
def test_revision_write_failure_rolls_back_ddl_and_data_then_retries(
        postgres_app, postgres_database, revision, previous, direction):
    with postgres_app.app_context():
        seed_graph(db.session, postgres_database.master)
        db.session.remove()
        migrate("downgrade", previous if direction == "upgrade" else revision)
        with db.engine.begin() as connection:
            connection.execute(text("""CREATE FUNCTION reject_revision() RETURNS trigger
                LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'revision write rejected'; END $$"""))
            connection.execute(text("""CREATE TRIGGER reject_revision BEFORE UPDATE ON alembic_version
                FOR EACH ROW EXECUTE FUNCTION reject_revision()"""))
        before = snapshot(db.engine)
        schema_before = {table: tuple(column["name"] for column in inspect(db.engine).get_columns(table))
                         for table in inspect(db.engine).get_table_names()}
        target = revision if direction == "upgrade" else previous
        with pytest.raises(DBAPIError, match="revision write rejected"):
            migrate(direction, target)
        assert snapshot(db.engine) == before
        assert {table: tuple(column["name"] for column in inspect(db.engine).get_columns(table))
                for table in inspect(db.engine).get_table_names()} == schema_before
        with db.engine.begin() as connection:
            connection.execute(text("DROP TRIGGER reject_revision ON alembic_version"))
            connection.execute(text("DROP FUNCTION reject_revision()"))
        migrate(direction, target)
        with db.engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == target
