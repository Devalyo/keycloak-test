import sqlite3

from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


@event.listens_for(Engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return

    previous_autocommit = getattr(dbapi_connection, "autocommit", None)
    if previous_autocommit is not None:
        dbapi_connection.autocommit = True
    try:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()
    finally:
        if previous_autocommit is not None:
            dbapi_connection.autocommit = previous_autocommit


db = SQLAlchemy(model_class=Base)
migrate = Migrate()


def database_engine_options(settings, overrides=None) -> dict:
    """Configure the final database dialect without adding SQLite pool options."""
    options = {}
    if settings.database_url.startswith('postgresql'):
        options.update(pool_pre_ping=True, pool_size=settings.database_pool_size,
                       max_overflow=settings.database_max_overflow,
                       pool_timeout=settings.database_pool_timeout_seconds,
                       pool_recycle=settings.database_pool_recycle_seconds)
    if overrides is not None:
        if not isinstance(overrides, dict):
            raise ValueError('MINI_KEYCLOAK_SQLALCHEMY_ENGINE_OPTIONS')
        if settings.profile == 'production' and any(
                key not in options or type(value) is not type(options[key]) or value != options[key]
                for key, value in overrides.items()):
            raise ValueError('MINI_KEYCLOAK_SQLALCHEMY_ENGINE_OPTIONS')
        options.update(overrides)
    return options


def validate_database_config(settings, config) -> None:
    """Close every Flask-SQLAlchemy configuration entry point in production."""
    if settings.profile != 'production':
        return
    fixed = {'SQLALCHEMY_BINDS': {}, 'SQLALCHEMY_ECHO': False,
             'SQLALCHEMY_RECORD_QUERIES': False, 'SQLALCHEMY_TRACK_MODIFICATIONS': False}
    supported = {'SQLALCHEMY_DATABASE_URI', 'SQLALCHEMY_ENGINE_OPTIONS', *fixed}
    for name in config:
        if name.startswith('SQLALCHEMY_') and name not in supported:
            raise ValueError('MINI_KEYCLOAK_' + name)
    for name, expected in fixed.items():
        value = config.get(name, expected)
        if type(value) is not type(expected) or value != expected:
            raise ValueError('MINI_KEYCLOAK_' + name)
        config[name] = expected
