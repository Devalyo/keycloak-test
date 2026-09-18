import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError

from mini_keycloak.extensions import db
from mini_keycloak.import_export.validation import RealmImportValidationError, validate_realm_import
from mini_keycloak.models import Client, Realm, SecurityEvent, User
from mini_keycloak.security.client_secrets import ClientSecretService
from mini_keycloak.security.passwords import PasswordService
from mini_keycloak.services.keys import RealmKeyService
from mini_keycloak.services.realm_import import RealmImportError
from tests.test_realm_import_service import PASSWORD, SECRET, apply, document, importer, snapshot


def assert_pending_state_rejected(db_app, monkeypatch, data, *, update):
    session = db.session()
    operations = []
    rollbacks = []

    def record_sql(*args):
        operations.append("sql")

    def record_flush(*args):
        operations.append("flush")

    def record_rollback(*args):
        rollbacks.append(True)

    def forbidden_work(*args, **kwargs):
        pytest.fail("Pending caller state must be rejected before credential/key work")

    with monkeypatch.context() as patch:
        patch.setattr(PasswordService, "hash", forbidden_work)
        patch.setattr(ClientSecretService, "hash", forbidden_work)
        patch.setattr(RealmKeyService, "ensure_active_key", forbidden_work)
        event.listen(db.engine, "before_cursor_execute", record_sql)
        event.listen(session, "before_flush", record_flush)
        event.listen(session, "after_rollback", record_rollback)
        try:
            with pytest.raises(RealmImportError) as exc:
                apply(db_app, data, update=update)
        finally:
            event.remove(db.engine, "before_cursor_execute", record_sql)
            event.remove(session, "before_flush", record_flush)
            event.remove(session, "after_rollback", record_rollback)

    assert str(exc.value) == "Realm import requires a clean session"
    assert PASSWORD not in str(exc.value) + repr(exc.value)
    assert SECRET not in str(exc.value) + repr(exc.value)
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None
    assert operations == []
    assert rollbacks == [True]
    assert not session.new and not session.dirty and not session.deleted
    assert session.is_active and not session.in_transaction()


@pytest.mark.parametrize("entity", ["realm", "client", "user", "email_owner"])
def test_pending_normalized_duplicates_are_rejected_before_work(db_app, monkeypatch, entity):
    with db_app.app_context():
        realm = Realm(name="Existing")
        db.session.add(realm)
        db.session.commit()
        realm_id = realm.id
        before = snapshot()
        data = {"realm": "Existing"}
        if entity == "realm":
            pending = Realm(name="Pending")
            data = {"realm": "PENDING"}
        elif entity == "client":
            pending = Client(realm_id=realm_id, client_id="Pending")
            data["clients"] = [{"clientId": "PENDING"}]
        elif entity == "user":
            pending = User(realm_id=realm_id, username="Pending", username_normalized="pending")
            data["users"] = [{"username": "PENDING"}]
        else:
            pending = User(realm_id=realm_id, username="Owner", username_normalized="owner",
                           email="Pending@Example.test", email_normalized="pending@example.test")
            data["users"] = [{"username": "New", "email": "PENDING@example.test"}]
        db.session.add(pending)

        assert_pending_state_rejected(db_app, monkeypatch, data, update=entity != "realm")

        assert pending not in db.session
        assert snapshot() == before


@pytest.mark.parametrize("model,field", [(Realm, "display_name"), (Client, "name"),
                                         (User, "first_name"), (SecurityEvent, "error")])
@pytest.mark.parametrize("state", ["new", "dirty", "deleted"])
def test_unrelated_pending_mutations_are_rolled_back_before_import(db_app, monkeypatch, model, field, state):
    with db_app.app_context():
        realm = Realm(name="Unrelated")
        db.session.add(realm)
        db.session.flush()
        realm_id = realm.id
        entities = {
            Realm: realm,
            Client: Client(realm_id=realm.id, client_id="Unrelated"),
            User: User(realm_id=realm.id, username="Unrelated", username_normalized="unrelated"),
            SecurityEvent: SecurityEvent(realm_id=realm.id, event_type="LOGIN"),
        }
        db.session.add_all(entities.values())
        db.session.commit()
        target = entities[model]
        # Load the original value before staging caller-owned work.
        original = getattr(target, field)
        before = snapshot()
        if state == "new":
            pending_entities = {
                Realm: Realm(name="Pending-unrelated"),
                Client: Client(realm_id=realm_id, client_id="Pending-unrelated"),
                User: User(realm_id=realm_id, username="Pending-unrelated",
                           username_normalized="pending-unrelated"),
                SecurityEvent: SecurityEvent(realm_id=realm_id, event_type="LOGIN"),
            }
            target = pending_entities[model]
            setattr(target, field, PASSWORD)
            db.session.add(target)
        elif state == "dirty":
            setattr(target, field, PASSWORD)
        else:
            db.session.delete(target)
        repr_calls = []

        def secret_repr(self):
            repr_calls.append(True)
            return SECRET

        monkeypatch.setattr(model, "__repr__", secret_repr)
        assert_pending_state_rejected(db_app, monkeypatch, document(), update=False)

        assert repr_calls == []
        if state == "new":
            assert target not in db.session
        else:
            assert target in db.session
            assert getattr(target, field) == original
        assert snapshot() == before
        # The same session can subsequently stage and flush the importer's work.
        realm = apply(db_app, document())
        db.session.commit()
        assert realm.name == "Imported"


@pytest.mark.parametrize("data,path", [
    ({"clients": [{"clientId": "Browser", "secret": SECRET}]}, "$.clients[0].secret"),
    ({"clients": [{"clientId": "New", "publicClient": False}]}, "$.clients[0].secret"),
    ({"clients": [{"clientId": "Browser", "publicClient": False}]}, "$.clients[0].secret"),
    ({"users": [{"username": "New", "email": "ALICE@example.test"}]}, "$.users[0].email"),
])
def test_effective_update_validation_fails_before_any_flush(db_app, data, path):
    with db_app.app_context():
        apply(db_app, document())
        db.session.commit()
        before = snapshot()
        data = {"realm": "Imported", "displayName": "must roll back", **data}
        flushes = []
        def record_flush(*args):
            flushes.append(True)
        session = db.session()
        event.listen(session, "before_flush", record_flush)
        try:
            with pytest.raises(RealmImportValidationError) as exc:
                apply(db_app, data, update=True)
        finally:
            event.remove(session, "before_flush", record_flush)
        assert any(issue.path == path for issue in exc.value.errors)
        assert not flushes
        assert snapshot() == before


@pytest.mark.parametrize("dependency,method", [(PasswordService, "hash"), (ClientSecretService, "hash"),
                                               (RealmKeyService, "ensure_active_key")])
@pytest.mark.parametrize("update", [False, True])
def test_hashing_or_key_failure_rolls_back_every_row_without_secret_diagnostics(db_app, monkeypatch, dependency, method, update):
    with db_app.app_context():
        if update:
            apply(db_app, document())
            db.session.commit()
        before = snapshot()
        data = document()
        data["displayName"] = "changed"
        data["clients"].insert(0, {"clientId": "New"})
        data["users"].insert(0, {"username": "New"})
        def fail(*args, **kwargs):
            raise RuntimeError(f"failure containing {PASSWORD} and {SECRET}")
        monkeypatch.setattr(dependency, method, fail)
        with pytest.raises(RealmImportError) as exc:
            apply(db_app, data, update=update)
        assert PASSWORD not in str(exc.value) + repr(exc.value)
        assert SECRET not in str(exc.value) + repr(exc.value)
        assert exc.value.__cause__ is None
        assert snapshot() == before


def test_database_failure_after_insert_rolls_back_realm_key_and_all_entities(db_app):
    with db_app.app_context():
        before = snapshot()
        # A database-level failure after realm, clients and user have been flushed.
        db.session.execute(db.text("CREATE TRIGGER fail_key BEFORE INSERT ON realm_keys BEGIN SELECT RAISE(ABORT, 'key rejected'); END"))
        db.session.commit()
        with pytest.raises(RealmImportError):
            apply(db_app, document())
        assert snapshot() == before


@pytest.mark.parametrize("entity", ["realm", "client"])
def test_normalized_database_constraints_preserve_existing_import_on_collision(db_app, entity):
    with db_app.app_context():
        realm = apply(db_app, document())
        db.session.commit()
        before = snapshot()
        if entity == "realm":
            db.session.add(Realm(name="IMPORTED"))
        else:
            db.session.add(Client(realm_id=realm.id, client_id="BROWSER"))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
        assert snapshot() == before
        apply(db_app, {"realm": "Imported", "clients": [{"clientId": "Browser"}]}, update=True)
        db.session.commit()
        assert snapshot() == before


def test_raw_documents_are_rejected_and_pending_changes_rolled_back(db_app):
    with db_app.app_context():
        db.session.add(Realm(name="pending"))
        with pytest.raises(RealmImportError):
            importer(db_app).import_realm(document())
        assert db.session.scalar(select(Realm)) is None


@pytest.mark.parametrize("entities", [
    {"clients": [{"clientId": "Test"}, {"clientId": "TEST"}]},
    {"users": [{"username": "Test"}, {"username": "TEST"}]},
    {"users": [{"username": "One", "email": "same@example.test"},
               {"username": "Two", "email": "SAME@example.test"}]},
])
def test_document_duplicates_fail_before_import(db_app, entities):
    with db_app.app_context():
        with pytest.raises(RealmImportValidationError) as exc:
            validate_realm_import({"realm": "Imported", **entities})
        assert exc.value.errors[0].message == "Duplicate normalized identifier"
        assert db.session.scalar(select(Realm)) is None
