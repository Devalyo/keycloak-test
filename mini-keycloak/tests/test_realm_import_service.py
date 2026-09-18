from datetime import timedelta

import pytest
from sqlalchemy import select

from mini_keycloak.extensions import db
from mini_keycloak.import_export.validation import validate_realm_import
from mini_keycloak.models import Client, Credential, Realm, RealmKey, User, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.oidc.errors import InvalidClient
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.clients import ClientService
from mini_keycloak.services.realm_import import RealmAlreadyExists, RealmImportService


PASSWORD = "Import-password-783!"
SECRET = "Import-client-secret-931!"


def document(name="Imported"):
    return {
        "realm": name, "displayName": "Imported realm", "enabled": True,
        "resetPasswordAllowed": False, "passwordPolicy": "length(12) and digits(1)",
        "accessTokenLifespan": 123, "accessCodeLifespan": 42,
        "ssoSessionIdleTimeout": 456, "ssoSessionMaxLifespan": 789,
        "attributes": {"mini.keycloak.passwordGrantEnabled": "true"},
        "clients": [
            {"clientId": "Browser", "name": "Browser app", "publicClient": True,
             "redirectUris": ["https://app.example/callback"],
             "webOrigins": ["https://app.example"], "directAccessGrantsEnabled": True,
             "defaultClientScopes": ["openid"], "optionalClientScopes": ["email"],
             "attributes": {"pkce.code.challenge.method": "optional",
                            "post.logout.redirect.uris": "https://app.example/bye##https://app.example/end"}},
            {"clientId": "Backend", "publicClient": False, "secret": SECRET,
             "directAccessGrantsEnabled": True},
        ],
        "users": [{"username": "Alice", "email": "Alice@Example.test",
                   "emailVerified": True, "firstName": "Alice", "lastName": "Person",
                   "attributes": {"team": ["engineering"]},
                   "credentials": [{"type": "password", "value": PASSWORD}]}],
    }


def importer(app):
    return RealmImportService(db.session, app.config["OIDC_KEY_ENCRYPTION_SECRET"])


def apply(app, data, *, update=False, preserve=False):
    return importer(app).import_realm(
        validate_realm_import(data, update=update).value, update=update,
        preserve_existing_credentials=preserve,
    )


def snapshot():
    return {
        table.name: sorted((tuple(repr(value) for value in row)
                            for row in db.session.execute(select(table))), key=repr)
        for table in db.metadata.sorted_tables
    }


@pytest.mark.parametrize("enabled", [True, False])
def test_import_persists_realm_policy_and_lifetimes(db_app, enabled):
    with db_app.app_context():
        data = document()
        data["enabled"] = enabled
        realm = apply(db_app, data)
        db.session.commit()
        assert realm.name == "Imported"
        assert realm.display_name == "Imported realm"
        assert realm.enabled is enabled
        assert realm.forgot_password_allowed is False
        assert realm.password_grant_enabled is True
        assert realm.password_policy == {"raw": "length(12) and digits(1)", "clauses": {"length": 12, "digits": 1}}
        assert (realm.access_token_lifetime_seconds, realm.authorization_code_lifetime_seconds,
                realm.sso_idle_lifetime_seconds, realm.sso_max_lifetime_seconds) == (123, 42, 456, 789)


def test_import_persists_clients_users_and_encrypted_signing_key(db_app):
    with db_app.app_context():
        realm = apply(db_app, document())
        db.session.commit()
        repository = IdentityRepository(db.session)
        browser = repository.get_client(realm.id, "Browser")
        assert browser.name == "Browser app"
        assert browser.redirect_uris == ["https://app.example/callback"]
        assert browser.web_origins == ["https://app.example"]
        assert browser.pkce_policy == "optional"
        assert browser.post_logout_redirect_uris == ["https://app.example/bye", "https://app.example/end"]
        assert browser.default_scopes == ["openid"]
        assert browser.optional_scopes == ["email"]
        user = repository.find_user(realm.id, " alice@EXAMPLE.test ")
        assert (user.username, user.first_name, user.last_name) == ("Alice", "Alice", "Person")
        assert user.attributes == {"team": ["engineering"]}
        assert user.email_verified
        key = db.session.scalars(select(RealmKey)).one()
        assert key.active and key.realm_id == realm.id
        assert "PRIVATE KEY" not in key.encrypted_private_pem
        assert key.public_jwk["kid"] == key.kid


def test_import_hashes_secrets_before_any_flush_and_supports_authentication(db_app):
    from sqlalchemy import event

    with db_app.app_context():
        def inspect_flush(session, context, instances):
            for obj in session.new | session.dirty:
                assert PASSWORD not in repr(vars(obj))
                assert SECRET not in repr(vars(obj))

        session = db.session()
        event.listen(session, "before_flush", inspect_flush)
        try:
            realm = apply(db_app, document())
            db.session.commit()
        finally:
            event.remove(session, "before_flush", inspect_flush)
        assert PASSWORD not in repr(snapshot())
        assert SECRET not in repr(snapshot())
        credential = db.session.scalars(select(Credential)).one()
        assert credential.secret_hash.startswith("$argon2id$")
        user = db.session.scalars(select(User)).one()
        assert IdentityRepository(db.session).password_matches(user, PASSWORD)
        service = ClientService(db.session)
        backend = service.authenticate(realm, "Backend", secret=SECRET, method="client_secret_post")
        assert backend.secret_hash.startswith("$argon2id$")
        assert service.authenticate(realm, "Browser").public_client
        with pytest.raises(InvalidClient):
            service.authenticate(realm, "Backend", secret="wrong", method="client_secret_post")


def test_duplicate_realm_is_case_normalized_and_has_no_mutation(db_app):
    with db_app.app_context():
        apply(db_app, document())
        db.session.commit()
        before = snapshot()
        with pytest.raises(RealmAlreadyExists):
            apply(db_app, {"realm": "IMPORTED", "displayName": "changed"})
        assert snapshot() == before


def test_update_preserves_omitted_fields_unlisted_entities_credentials_and_sessions(db_app):
    with db_app.app_context():
        realm = apply(db_app, document())
        user = db.session.scalars(select(User)).one()
        browser = db.session.scalar(select(Client).where(Client.client_id == "Browser"))
        session = UserSession(realm_id=realm.id, client_id=browser.id, user_id=user.id,
                              idle_expires_at=utc_now() + timedelta(hours=1),
                              max_expires_at=utc_now() + timedelta(hours=2))
        db.session.add(session)
        db.session.commit()
        before = snapshot()
        ids = (realm.id, browser.id, user.id)
        updated = apply(db_app, {"realm": "imported", "displayName": "Changed",
                                "clients": [{"clientId": "BROWSER", "name": "Renamed"}],
                                "users": [{"username": "ALICE", "firstName": "New"}]}, update=True)
        db.session.commit()
        assert updated.id == ids[0]
        assert browser.id == ids[1] and browser.name == "Renamed"
        assert user.id == ids[2] and user.first_name == "New"
        assert updated.display_name == "Changed" and updated.password_grant_enabled
        assert browser.redirect_uris == ["https://app.example/callback"]
        assert browser.pkce_policy == "optional" and len(browser.post_logout_redirect_uris) == 2
        assert user.email == "Alice@Example.test" and user.attributes == {"team": ["engineering"]}
        after = snapshot()
        for table in ("credentials", "realm_keys", "user_sessions"):
            assert after[table] == before[table]
        assert len(after["clients"]) == 2 and len(after["users"]) == 1
        assert db.session.scalar(select(Client).where(Client.client_id == "Backend")).secret_hash


def test_update_applies_explicit_false_empty_and_null_fields(db_app):
    with db_app.app_context():
        apply(db_app, document())
        db.session.commit()
        realm = apply(db_app, {"realm": "Imported", "enabled": False, "displayName": None,
                              "passwordPolicy": "", "attributes": {"mini.keycloak.passwordGrantEnabled": "false"},
                              "clients": [{"clientId": "Browser", "enabled": False, "name": None,
                                           "redirectUris": [], "webOrigins": [], "defaultClientScopes": [],
                                           "optionalClientScopes": [], "standardFlowEnabled": False,
                                           "directAccessGrantsEnabled": False,
                                           "attributes": {"post.logout.redirect.uris": ""}}],
                              "users": [{"username": "Alice", "email": None, "enabled": False,
                                         "emailVerified": False, "firstName": "", "lastName": None,
                                         "attributes": {}, "credentials": []}]}, update=True)
        db.session.commit()
        browser = db.session.scalar(select(Client).where(Client.client_id == "Browser"))
        user = db.session.scalars(select(User)).one()
        assert not realm.enabled and realm.display_name is None and not realm.password_grant_enabled
        assert realm.password_policy == {"raw": "", "clauses": {}}
        assert not browser.enabled and not browser.standard_flow_enabled and not browser.direct_access_grants_enabled
        assert browser.name is None
        assert browser.redirect_uris == browser.web_origins == browser.default_scopes == browser.optional_scopes == []
        assert browser.post_logout_redirect_uris == [] and browser.pkce_policy == "optional"
        assert not user.enabled and not user.email_verified
        assert user.email is user.email_normalized is user.last_name is None
        assert user.first_name == "" and user.attributes == {}
        assert IdentityRepository(db.session).password_matches(user, PASSWORD)


@pytest.mark.parametrize("preserve", [False, True])
def test_update_rotates_only_supplied_credentials_unless_preserved(db_app, preserve):
    with db_app.app_context():
        realm = apply(db_app, document())
        db.session.commit()
        credential = db.session.scalars(select(Credential)).one()
        original_credential = (credential.id, credential.secret_hash)
        backend = db.session.scalar(select(Client).where(Client.client_id == "Backend"))
        original_secret = backend.secret_hash
        key_id = db.session.scalars(select(RealmKey)).one().id
        apply(db_app, {"realm": "Imported", "clients": [{"clientId": "Backend", "secret": "New-secret!"}],
                       "users": [{"username": "Alice", "credentials": [{"type": "password", "value": "New-password1!"}]},
                                 {"username": "New", "credentials": [{"type": "password", "value": "Created-password1!"}]}]},
              update=True, preserve=preserve)
        db.session.commit()
        repository = IdentityRepository(db.session)
        assert repository.password_matches(repository.find_user(realm.id, "Alice"), PASSWORD if preserve else "New-password1!")
        assert repository.password_matches(repository.find_user(realm.id, "New"), "Created-password1!")
        assert credential.id == original_credential[0]
        assert (credential.secret_hash == original_credential[1]) is preserve
        assert (backend.secret_hash == original_secret) is preserve
        ClientService(db.session).authenticate(realm, "Backend", secret=SECRET if preserve else "New-secret!", method="client_secret_post")
        assert db.session.scalars(select(RealmKey)).one().id == key_id


def test_second_realm_import_and_update_do_not_resolve_first_realm_identities(db_app):
    with db_app.app_context():
        first = apply(db_app, document())
        db.session.commit()
        first_id = first.id
        before = snapshot()
        second = apply(db_app, {"realm": "Second", "clients": [{"clientId": "Browser"}],
                               "users": [{"username": "Alice", "email": "Alice@Example.test"}]}, update=True)
        db.session.commit()
        repository = IdentityRepository(db.session)
        assert second.id != first_id
        assert repository.get_client(first_id, "Browser").id != repository.get_client(second.id, "Browser").id
        second_user = repository.find_user(second.id, "Alice")
        assert not repository.password_matches(second_user, PASSWORD)
        assert repository.get_user(second.id, repository.find_user(first_id, "Alice").id) is None
        with pytest.raises(InvalidClient):
            ClientService(db.session).authenticate(second, "Backend", secret=SECRET, method="client_secret_post")
        after = snapshot()
        for table, rows in before.items():
            assert all(row in after[table] for row in rows)


@pytest.mark.parametrize("preserve", [False, True])
def test_update_preserves_absent_credentials_only_when_requested(db_app, preserve):
    with db_app.app_context():
        realm = apply(db_app, document())
        repository = IdentityRepository(db.session)
        user = repository.find_user(realm.id, "Alice")
        backend = repository.get_client(realm.id, "Backend")
        db.session.delete(db.session.scalar(select(Credential).where(Credential.user_id == user.id)))
        backend.secret_hash = None
        db.session.commit()
        data = document()
        data["clients"].append({"clientId": "New-backend", "publicClient": False, "secret": "Created-secret!"})
        data["users"].append({"username": "New", "credentials": [{"type": "password", "value": "Created-password1!"}]})
        apply(db_app, data, update=True, preserve=preserve)
        db.session.commit()
        assert repository.password_matches(user, PASSWORD) is not preserve
        credential = db.session.scalar(select(Credential).where(Credential.user_id == user.id))
        assert (credential is None) is preserve
        assert (backend.secret_hash is None) is preserve
        clients = ClientService(db.session)
        if preserve:
            with pytest.raises(InvalidClient):
                clients.authenticate(realm, "Backend", secret=SECRET, method="client_secret_post")
        else:
            assert clients.authenticate(realm, "Backend", secret=SECRET, method="client_secret_post") == backend
        assert repository.password_matches(repository.find_user(realm.id, "New"), "Created-password1!")
        assert clients.authenticate(realm, "New-backend", secret="Created-secret!", method="client_secret_post")


@pytest.mark.parametrize("preserve", [False, True])
def test_update_client_type_preserves_secret_only_when_requested(db_app, preserve):
    with db_app.app_context():
        realm = apply(db_app, document())
        backend = IdentityRepository(db.session).get_client(realm.id, "Backend")
        db.session.commit()
        original_secret = backend.secret_hash
        apply(db_app, {"realm": "Imported", "clients": [{"clientId": "Backend", "publicClient": True}]},
              update=True, preserve=preserve)
        db.session.commit()
        assert backend.public_client
        assert backend.secret_hash == (original_secret if preserve else None)


def test_import_does_not_commit_and_key_ensure_is_idempotent(db_app):
    with db_app.app_context():
        apply(db_app, document())
        db.session.rollback()
        assert all(not rows for rows in snapshot().values())
        apply(db_app, document())
        db.session.commit()
        before = snapshot()
        apply(db_app, {"realm": "Imported"}, update=True)
        db.session.commit()
        assert snapshot() == before


def test_update_can_transfer_or_swap_unique_emails_atomically(db_app):
    with db_app.app_context():
        apply(db_app, {"realm": "Imported", "users": [
            {"username": "Alice", "email": "alice@example.test"},
            {"username": "Bob", "email": "bob@example.test"}]})
        db.session.commit()
        realm = apply(db_app, {"realm": "Imported", "users": [
            {"username": "Alice", "email": "bob@example.test"},
            {"username": "Bob", "email": "alice@example.test"}]}, update=True)
        db.session.commit()
        repository = IdentityRepository(db.session)
        assert repository.find_user(realm.id, "alice@example.test").username == "Bob"
        assert repository.find_user(realm.id, "bob@example.test").username == "Alice"
