"""Use a fresh private schema; never reset the supplied database or public."""

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import secrets

from flask_migrate import downgrade, upgrade
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.schema import CreateSchema, DropSchema

from mini_keycloak.app import create_app
from mini_keycloak.extensions import db


MIGRATIONS = str(Path(__file__).parents[2] / "migrations")
SCHEMA_PATTERN = re.compile(r"mk_test_[0-9a-f]{32}\Z")


@dataclass(repr=False)
class PostgresDatabase:
    url: str
    schema: str
    applications: list = field(default_factory=list)
    secret: str = field(default_factory=lambda: secrets.token_urlsafe(48))
    master: str = field(default_factory=lambda: secrets.token_urlsafe(48))

    def app(self, **overrides):
        application = create_app({
            "TESTING": True, "PROFILE": "production",
            "SQLALCHEMY_DATABASE_URI": self.url,
            "SECRET_KEY": self.secret, "OIDC_KEY_ENCRYPTION_SECRET": self.master,
            "EXTERNAL_URL": "https://identity.example.test",
            "SESSION_COOKIE_SECURE": True, "TRUSTED_HOSTS": ["identity.example.test"],
            "PROXY_MODE": "none", **overrides,
        })
        self.applications.append(application)
        with application.app_context():
            # Configure the connection only in test support: production URL
            # validation must continue rejecting arbitrary driver options.
            event.listen(db.engine, "connect", self.configure_connection)
        return application

    def configure_connection(self, connection, record):
        assert SCHEMA_PATTERN.fullmatch(self.schema), "Unsafe test schema"
        previous = connection.autocommit
        connection.autocommit = True
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('search_path', %s, false)", (self.schema,))
                cursor.execute("SET statement_timeout = '15s'")
                cursor.execute("SET lock_timeout = '10s'")
        finally:
            connection.autocommit = previous


@pytest.fixture
def postgres_database(monkeypatch):
    url = os.environ.get("MINI_KEYCLOAK_TEST_POSTGRES_URL")
    if url is None:
        pytest.skip("MINI_KEYCLOAK_TEST_POSTGRES_URL is not set")
    # An invalid/empty supplied URL is a failure, never a silent skip.
    assert make_url(url).drivername == "postgresql+psycopg", "Tests require psycopg 3"
    administrator = create_engine(url, hide_parameters=True, pool_pre_ping=True)
    schema = "mk_test_" + secrets.token_hex(16)
    assert SCHEMA_PATTERN.fullmatch(schema), "Unsafe test schema"
    database = PostgresDatabase(url, schema)
    created = False
    # Avoid Alembic's process-wide logging reset disabling pytest capture.
    monkeypatch.setattr("logging.config.fileConfig", lambda *args, **kwargs: None)
    try:
        with administrator.begin() as connection:
            version = int(connection.scalar(text("SHOW server_version_num")))
            assert 170000 <= version < 180000, "Live tests require PostgreSQL 17"
            connection.execute(CreateSchema(schema))
            created = True
        yield database
    finally:
        for application in database.applications:
            with application.app_context():
                db.session.remove()
                db.engine.dispose()
        try:
            if created:
                assert SCHEMA_PATTERN.fullmatch(schema), "Unsafe schema cleanup"
                with administrator.begin() as connection:
                    connection.execute(DropSchema(schema, cascade=True))
        finally:
            administrator.dispose()


@pytest.fixture
def postgres_app(postgres_database):
    application = postgres_database.app()
    with application.app_context():
        upgrade(directory=MIGRATIONS, revision="head")
        with db.engine.connect() as connection:
            assert connection.scalar(text("SELECT current_schema()")) == postgres_database.schema
    return application


def migrate(direction, revision):
    (upgrade if direction == "upgrade" else downgrade)(directory=MIGRATIONS, revision=revision)
