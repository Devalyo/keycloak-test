"""Production configuration and generic health behavior on the real driver."""

import secrets
import socket

import pytest
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import make_url

from mini_keycloak.extensions import db
from mini_keycloak.models import RealmKey
from .support import seed_graph


pytestmark = pytest.mark.postgres
ORIGIN = "https://identity.example.test"


def test_production_readiness_and_liveness_are_read_only_and_secret_safe(
        postgres_app, postgres_database, caplog, capsys):
    with postgres_app.app_context():
        graph = seed_graph(db.session, postgres_database.master)
        private = db.session.scalar(select(RealmKey.encrypted_private_pem))
        db.session.remove()
        statements = []

        def capture(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(db.engine, "before_cursor_execute", capture)
        try:
            client = postgres_app.test_client()
            live = client.get("/health/live?secret=query-private-sentinel", base_url=ORIGIN)
            assert (live.status_code, live.json) == (200, {"status": "ok"})
            assert statements == []
            ready = client.get("/health/ready?secret=query-private-sentinel", base_url=ORIGIN,
                               headers={"Authorization": "Bearer header-private-sentinel"})
            assert (ready.status_code, ready.json) == (200, {"status": "ok"})
            assert statements and all(statement.lstrip().upper().startswith("SELECT") for statement in statements)
            assert not db.session.registry.has()
            assert postgres_app.config["PROFILE"] == "production"
            assert db.engine.dialect.name == "postgresql" and db.engine.dialect.driver == "psycopg"
        finally:
            event.remove(db.engine, "before_cursor_execute", capture)
        output = capsys.readouterr()
        diagnostic = output.out + output.err + caplog.text + live.text + ready.text
        assert not any(value in diagnostic for value in (
            postgres_database.url, postgres_database.secret, postgres_database.master, private,
            graph.refresh, "query-private-sentinel", "header-private-sentinel", "PRIVATE KEY"))


def test_readiness_rejects_wrong_master_with_fixed_error(postgres_app, postgres_database, caplog, capsys):
    with postgres_app.app_context():
        seed_graph(db.session, postgres_database.master)
        private = db.session.scalar(select(RealmKey.encrypted_private_pem))
        db.session.remove()
    wrong_master = secrets.token_urlsafe(48)
    application = postgres_database.app(OIDC_KEY_ENCRYPTION_SECRET=wrong_master)
    caplog.clear()
    response = application.test_client().get("/health/ready?token=query-private-sentinel", base_url=ORIGIN)
    assert (response.status_code, response.json) == (503, {"status": "unavailable"})
    assert application.test_client().get("/health/live", base_url=ORIGIN).status_code == 200
    assert [record.getMessage() for record in caplog.records] == ["Health readiness check failed"]
    assert all(record.exc_info is None for record in caplog.records)
    output = capsys.readouterr()
    diagnostic = response.text + caplog.text + output.out + output.err
    assert not any(value in diagnostic for value in (
        postgres_database.url, postgres_database.master, wrong_master, private, "query-private-sentinel"))


def test_unreachable_database_has_generic_readiness_and_independent_liveness(postgres_database, caplog, capsys):
    # Hold a local port without listening, so refusal is deterministic and no
    # external database/container needs stopping.
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        unreachable = make_url(postgres_database.url).set(host="127.0.0.1", port=reserved.getsockname()[1])
        unreachable = unreachable.update_query_dict({"connect_timeout": "1"}).render_as_string(hide_password=False)
        application = postgres_database.app(SQLALCHEMY_DATABASE_URI=unreachable)
        caplog.clear()
        client = application.test_client()
        live = client.get("/health/live", base_url=ORIGIN)
        response = client.get("/health/ready", base_url=ORIGIN)
        assert (live.status_code, live.json) == (200, {"status": "ok"})
        assert (response.status_code, response.json) == (503, {"status": "unavailable"})
        assert [record.getMessage() for record in caplog.records] == ["Health readiness check failed"]
        assert all(record.exc_info is None for record in caplog.records)
        output = capsys.readouterr()
        diagnostic = output.out + output.err + caplog.text + response.text
        assert not any(value in diagnostic for value in (
            unreachable, make_url(unreachable).password, "OperationalError", "connection refused"))


def test_pool_pre_ping_replaces_a_terminated_idle_connection(postgres_app, postgres_database):
    administrator = create_engine(postgres_database.url, hide_parameters=True)
    try:
        with postgres_app.app_context():
            engine = db.engine
            with engine.connect() as connection:
                old_pid = connection.scalar(text("SELECT pg_backend_pid()"))
            with administrator.connect() as connection:
                assert connection.scalar(text("SELECT pg_terminate_backend(:pid)"), {"pid": old_pid}) is True
            with engine.connect() as connection:
                assert connection.scalar(text("SELECT pg_backend_pid()")) != old_pid
                assert connection.scalar(text("SELECT current_schema()")) == postgres_database.schema
            assert postgres_app.test_client().get("/health/ready", base_url=ORIGIN).status_code == 200
    finally:
        administrator.dispose()
