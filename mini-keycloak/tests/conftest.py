from dataclasses import dataclass
from threading import Thread

import pytest

from werkzeug.serving import make_server

from mini_keycloak.app import create_app
from mini_keycloak.extensions import db
from mini_keycloak.services.bootstrap import ensure_demo_realm


@dataclass
class LiveServer:
    url: str


@pytest.fixture
def app(tmp_path):
    database = tmp_path / "test.sqlite3"
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite+pysqlite:///{database}",
        }
    )
    with application.app_context():
        db.create_all()
        ensure_demo_realm(db.session)
        db.session.commit()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def live_server(app):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield LiveServer(url=f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def db_app(tmp_path):
    database = tmp_path / "test.sqlite3"
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite+pysqlite:///{database}",
        }
    )
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()
