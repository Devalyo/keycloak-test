import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from mini_keycloak.extensions import db
from mini_keycloak.models import Credential


def test_sqlite_application_connections_enforce_foreign_keys(db_app):
    with db_app.app_context():
        assert db.session.scalar(text("PRAGMA foreign_keys")) == 1


def test_sqlite_rejects_orphaned_foreign_key_rows(db_app):
    with db_app.app_context():
        db.session.add(
            Credential(
                user_id="missing-user",
                type="password",
                secret_hash="not-a-real-password-hash",
            )
        )

        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
