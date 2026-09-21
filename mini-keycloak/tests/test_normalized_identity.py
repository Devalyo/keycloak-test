from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from mini_keycloak.extensions import db
from mini_keycloak.import_export.validation import validate_realm_import
from mini_keycloak.models import Client, Credential, Realm, RealmKey, User
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.realm_import import RealmImportError, RealmImportService


def test_normalized_identity_persists_exact_casefold_and_tracks_spelling_changes(db_app):
    with db_app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.create_realm("  Straße  ")
        client = repository.create_client(realm.id, "  Straße-ﬃ  ", redirect_uris=[])
        db.session.commit()
        assert (realm.name, realm.name_normalized) == ("  Straße  ", "strasse")
        assert (client.client_id, client.client_id_normalized) == ("  Straße-ﬃ  ", "strasse-ffi")
        assert repository.realms_with_normalized_name("strasse") == [realm]
        realm.name = "  Renamed  "
        client.client_id = "  Renamed-ﬃ  "
        db.session.commit()
        assert realm.name_normalized == "renamed"
        assert client.client_id_normalized == "renamed-ffi"
        assert repository.realms_with_normalized_name("strasse") == []
        assert repository.realms_with_normalized_name("renamed") == [realm]
        # Protocol-facing exact identifier lookup stays exact.
        assert repository.get_realm("renamed") is None
        assert repository.get_client(realm.id, "renamed-ffi") is None


@pytest.mark.parametrize("entity", ["realm", "client"])
def test_database_rejects_normalized_duplicates_outside_importer(db_app, entity):
    with db_app.app_context():
        realm = Realm(name="  Straße  ")
        db.session.add(realm)
        db.session.flush()
        first = Client(realm_id=realm.id, client_id="  Straße-ﬃ  ")
        db.session.add(first)
        db.session.commit()
        if entity == "realm":
            db.session.add(Realm(name="STRASSE"))
        else:
            other = Realm(name="other")
            db.session.add(other)
            db.session.flush()
            db.session.add(Client(realm_id=other.id, client_id="STRASSE-FFI"))
            db.session.commit()
            db.session.add(Client(realm_id=realm.id, client_id="STRASSE-FFI"))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


@pytest.mark.parametrize("entity", ["realm", "client"])
def test_concurrent_case_variants_have_one_committed_winner_and_safe_rollback(db_app, monkeypatch, entity):
    barrier = Barrier(2)
    original_preflight = RealmImportService._preflight

    def synchronized_preflight(self, *args, **kwargs):
        result = original_preflight(self, *args, **kwargs)
        barrier.wait(timeout=10)
        return result

    with db_app.app_context():
        engine = db.engine
        master_secret = db_app.config["OIDC_KEY_ENCRYPTION_SECRET"]
        if entity == "client":
            RealmImportService(db.session, master_secret).import_realm(
                validate_realm_import({"realm": "Concurrent"}).value)
            db.session.commit()
        db.session.remove()

    def import_variant(index):
        name = ("Concurrent", "CONCURRENT")[index]
        client_id = ("Straße-App", "STRASSE-APP")[index]
        password = f"parallel-password-{index}!"
        secret = f"parallel-client-secret-{index}!"
        value = validate_realm_import({
            "realm": name,
            "clients": [{"clientId": client_id, "publicClient": False, "secret": secret}],
            "users": [{"username": f"worker-{index}", "credentials": [
                {"type": "password", "value": password}]}],
        }, update=entity == "client").value
        with Session(engine) as session:
            rollbacks = []
            event.listen(session, "after_rollback", lambda _: rollbacks.append(True))
            try:
                RealmImportService(session, master_secret).import_realm(value, update=entity == "client")
                session.commit()
                return "committed", index
            except RealmImportError as error:
                assert str(error) == "Realm import failed"
                assert error.__cause__ is None and error.__context__ is None
                assert password not in str(error) + repr(error)
                assert secret not in str(error) + repr(error)
                assert rollbacks == [True]
                assert session.is_active and not session.in_transaction()
                assert not session.new and not session.dirty and not session.deleted
                return "rolled back", index

    with monkeypatch.context() as patch:
        patch.setattr(RealmImportService, "_preflight", synchronized_preflight)
        with ThreadPoolExecutor(max_workers=2) as workers:
            outcomes = list(workers.map(import_variant, range(2)))
    assert sorted(state for state, _ in outcomes) == ["committed", "rolled back"]
    winner = next(index for state, index in outcomes if state == "committed")

    with db_app.app_context():
        realm = db.session.scalars(select(Realm)).one()
        client = db.session.scalars(select(Client)).one()
        user = db.session.scalars(select(User)).one()
        assert user.username == f"worker-{winner}"
        assert db.session.scalars(select(Credential)).one().user_id == user.id
        assert db.session.scalars(select(RealmKey)).one().realm_id == realm.id
        assert realm.name_normalized == "concurrent"
        assert client.client_id_normalized == "strasse-app"
        spelling = (realm.name, client.client_id)
        identities = (realm.id, client.id)
        RealmImportService(db.session, master_secret).import_realm(validate_realm_import({
            "realm": "concurrent", "displayName": "Still updateable",
            "clients": [{"clientId": "strasse-app", "name": "Updated client"}],
        }, update=True).value, update=True)
        db.session.commit()
        assert (realm.id, client.id) == identities
        assert (realm.name, client.client_id) == spelling
        assert (realm.display_name, client.name) == ("Still updateable", "Updated client")
