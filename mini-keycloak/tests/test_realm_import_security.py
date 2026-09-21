"""Import boundary regressions using ordinary local realms only."""

import gc
import json
import weakref
from pathlib import Path

import pytest
from sqlalchemy import event, select

from mini_keycloak.extensions import db
from mini_keycloak.import_export.io import RealmImportIOError, read_realm_document
from mini_keycloak.import_export.validation import RealmImportValidationError, validate_realm_import
from mini_keycloak.models import Client, Credential, RealmKey, SecurityEvent, User
from mini_keycloak.services.keys import RealmKeyService
from mini_keycloak.security.passwords import PasswordService
from mini_keycloak.services.realm_import import RealmImportError
from tests.test_realm_import_service import PASSWORD, SECRET, apply, document, importer, snapshot


FIXTURES = Path(__file__).parent / "fixtures" / "realm-import"


def write_document(tmp_path, data):
    path = tmp_path / "realm.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize("policy,password", [
    ("length(8)", "Short1!"),
    ("digits(2)", "Onlyone1!"),
    ("lowerCase(2)", "ONLYONEa1!"),
    ("upperCase(2)", "onlyoneA1!"),
    ("specialChars(2)", "Onlyone1!"),
])
@pytest.mark.parametrize("update", [False, True])
def test_imported_password_must_meet_effective_policy_before_hash_or_flush(db_app, monkeypatch, policy, password, update):
    with db_app.app_context():
        if update:
            apply(db_app, {"realm": "policy", "passwordPolicy": policy, "users": [{"username": "alice"}]})
            db.session.commit()
        before = snapshot()
        data = {"realm": "policy", "users": [{"username": "alice", "credentials": [
            {"type": "password", "value": password}]}]}
        if not update:
            data["passwordPolicy"] = policy
        operations = []

        def record_flush(*args):
            operations.append("flush")

        def forbidden_hash(*args):
            pytest.fail("Policy rejection must happen before hashing")

        session = db.session()
        event.listen(session, "before_flush", record_flush)
        monkeypatch.setattr(PasswordService, "hash", forbidden_hash)
        try:
            with pytest.raises(RealmImportValidationError) as error:
                apply(db_app, data, update=update)
        finally:
            event.remove(session, "before_flush", record_flush)
        assert [(issue.path, issue.message) for issue in error.value.errors] == [
            ("$.users[0].credentials[0].value", "Password does not satisfy realm policy")]
        assert password not in str(error.value) + repr(error.value)
        assert operations == []
        assert snapshot() == before


def test_policy_update_uses_final_policy_and_only_checks_changed_credentials(db_app):
    with db_app.app_context():
        realm = apply(db_app, {"realm": "policy", "passwordPolicy": "length(20)",
                               "users": [{"username": "alice", "credentials": [
                                   {"type": "password", "value": "Original-long-password-123!"}]}]})
        db.session.commit()
        credential = db.session.scalar(select(Credential))
        original_hash = credential.secret_hash
        apply(db_app, {"realm": "policy", "passwordPolicy": "length(4096)",
                       "users": [{"username": "alice"}]}, update=True)
        db.session.commit()
        assert credential.secret_hash == original_hash
        apply(db_app, {"realm": "policy", "users": [{"username": "alice", "credentials": [
            {"type": "password", "value": "preserved"}]}]}, update=True, preserve=True)
        db.session.commit()
        assert credential.secret_hash == original_hash
        apply(db_app, {"realm": "policy", "passwordPolicy": "length(8) and digits(1) and lowerCase(1) and upperCase(1) and specialChars(1)",
                       "users": [{"username": "alice", "credentials": [
                           {"type": "password", "value": "Changed1!"}]}]}, update=True)
        db.session.commit()
        assert credential.secret_hash != original_hash
        assert realm.password_policy["clauses"]["length"] == 8


def test_preservation_still_checks_new_users_against_effective_policy(db_app):
    with db_app.app_context():
        apply(db_app, {"realm": "policy", "passwordPolicy": "length(20)"})
        db.session.commit()
        before = snapshot()
        with pytest.raises(RealmImportValidationError):
            apply(db_app, {"realm": "policy", "users": [{"username": "new", "credentials": [
                {"type": "password", "value": "short"}]}]}, update=True, preserve=True)
        assert snapshot() == before


@pytest.mark.parametrize("control", ["\x00", "\n", "\x7f", "\x85"])
def test_controls_in_ignored_values_fail_before_mutation(db_app, tmp_path, control):
    data = document()
    data["unsupported"] = {"nested": SECRET + control}
    result = db_app.test_cli_runner().invoke(args=["realm-import", str(write_document(tmp_path, data))])
    assert result.exit_code != 0
    assert SECRET not in result.output
    with db_app.app_context():
        assert not any(snapshot().values())


@pytest.mark.parametrize("kind", ["depth", "nodes"])
def test_reader_enforces_structural_budget_before_returning_document(tmp_path, kind):
    data = {"realm": "bounded"}
    if kind == "depth":
        nested = []
        data["ignored"] = nested
        for _ in range(17):
            child = []
            nested.append(child)
            nested = child
    else:
        data["ignored"] = [None] * 50000
    path = write_document(tmp_path, data)
    with pytest.raises(RealmImportIOError, match="structural") as error:
        read_realm_document(path)
    assert error.value.__cause__ is error.value.__context__ is None


def test_validation_failure_releases_document_and_partial_dto(monkeypatch):
    # The public exception must not retain partially parsed credential DTOs.
    from mini_keycloak.import_export import validation

    original = validation._Validator.realm
    references = []

    def observe(self, data):
        value = original(self, data)
        references.extend([weakref.ref(value), weakref.ref(value.users[0].credentials[0])])
        return value

    monkeypatch.setattr(validation._Validator, "realm", observe)
    with pytest.raises(RealmImportValidationError) as error:
        validate_realm_import({**document(), "enabled": "invalid"})
    gc.collect()
    assert all(reference() is None for reference in references)
    assert error.value.__context__ is error.value.__cause__ is None
    assert PASSWORD not in repr(error.value) and SECRET not in repr(error.value)


@pytest.mark.parametrize("failure", ["preflight", "after_flush"])
def test_service_failure_releases_import_dtos(db_app, monkeypatch, failure):
    with db_app.app_context():
        apply(db_app, document())
        db.session.commit()
        before = snapshot()
        references = []

        def attempt():
            data = document()
            if failure == "preflight":
                data["clients"][0].pop("publicClient")
                data["clients"][0]["secret"] = SECRET
            value = validate_realm_import(data, update=True).value
            references.extend([weakref.ref(value), weakref.ref(value.users[0]),
                               weakref.ref(value.clients[-1])])
            try:
                importer(db_app).import_realm(value, update=True)
            finally:
                del value, data

        if failure == "after_flush":
            def fail(*args):
                raise RuntimeError(PASSWORD + SECRET)
            monkeypatch.setattr(RealmKeyService, "ensure_active_key", fail)
        with pytest.raises((RealmImportError, RealmImportValidationError)) as error:
            attempt()
        gc.collect()
        assert references and all(reference() is None for reference in references)
        assert PASSWORD not in repr(error.value) and SECRET not in repr(error.value)
        assert snapshot() == before


@pytest.mark.parametrize("update", [False, True])
def test_cli_commit_failure_rolls_back_before_output_and_releases_dto(db_app, tmp_path, monkeypatch, caplog, update):
    from mini_keycloak import cli

    original_validate = cli.validate_realm_import
    references = []

    def observe(*args, **kwargs):
        result = original_validate(*args, **kwargs)
        references.append(weakref.ref(result.value))
        return result

    path = write_document(tmp_path, {**document(), "displayName": "Changed"})
    with db_app.app_context():
        if update:
            apply(db_app, document())
            db.session.commit()
        before = snapshot()
        operations = []
        session = db.session()
        def rolled_back(*args):
            operations.append("rollback")
        event.listen(session, "after_rollback", rolled_back)

        def fail():
            assert db.session.scalar(select(Credential)) is not None
            assert db.session.scalar(select(RealmKey)) is not None
            raise RuntimeError(PASSWORD + SECRET)

        monkeypatch.setattr(cli, "validate_realm_import", observe)
        monkeypatch.setattr(db.session, "commit", fail)
        original_show = cli.click.ClickException.show

        def show(self, *args, **kwargs):
            assert operations == ["rollback"]
            assert snapshot() == before
            return original_show(self, *args, **kwargs)

        monkeypatch.setattr(cli.click.ClickException, "show", show)
        try:
            args = ["realm-import", str(path)] + (["--update"] if update else [])
            result = db_app.test_cli_runner().invoke(args=args)
        finally:
            event.remove(session, "after_rollback", rolled_back)
        assert result.exit_code != 0 and "Realm import failed" in result.output
        assert operations == ["rollback"]
        assert snapshot() == before
        assert not db.session.scalars(select(SecurityEvent)).all()
        for secret in (PASSWORD, SECRET):
            assert secret not in result.output + caplog.text + repr(result.exception)
        gc.collect()
        assert references and references[0]() is None


@pytest.mark.parametrize("change", [
    {"realm": "../other"},
    {"clients": [{"clientId": "unsafe", "redirectUris": ["https://user:pass@example.test/cb"]}]},
    {"clients": [{"clientId": "unsafe", "redirectUris": ["https://example.test/cb#fragment"]}]},
    {"clients": [{"clientId": "unsafe", "redirectUris": ["https://example.test/*"]}]},
    {"clients": [{"clientId": "unsafe", "redirectUris": ["file:///tmp/cb"]}]},
    {"users": [{"username": "unsafe", "credentials": [{"type": "password", "value": PASSWORD, "algorithm": "argon2"}]}]},
    {"users": [{"username": "user" + str(i)} for i in range(1001)]},
    {"users": [{"username": "unsafe", "attributes": {str(i): ["value"] for i in range(65)}}]},
])
def test_invalid_inputs_fail_without_mutation_or_secret_output(db_app, tmp_path, caplog, change):
    data = {**document(), **change}
    result = db_app.test_cli_runner().invoke(args=["realm-import", str(write_document(tmp_path, data))])
    assert result.exit_code != 0 and "Error:" in result.output
    for secret in (PASSWORD, SECRET):
        assert secret not in result.output + caplog.text + repr(result.exception)
    with db_app.app_context():
        assert not any(snapshot().values())


def test_crafted_foreign_ids_are_ignored_and_cannot_reassign_entities(db_app):
    with db_app.app_context():
        first = apply(db_app, document())
        db.session.commit()
        first_id = first.id
        user_id = db.session.scalar(select(User.id))
        client_id = db.session.scalar(select(Client.id))
        before = snapshot()
        data = {"realm": "Other", "id": first_id,
                "clients": [{"clientId": "Browser", "id": client_id, "realmId": first_id}],
                "users": [{"username": "Alice", "id": user_id, "realmId": first_id}]}
        parsed = validate_realm_import(data)
        assert len(parsed.warnings) == 5
        other = importer(db_app).import_realm(parsed.value)
        db.session.commit()
        assert other.id != first_id
        assert db.session.scalar(select(User.id).where(User.realm_id == other.id)) != user_id
        assert db.session.scalar(select(Client.id).where(Client.realm_id == other.id)) != client_id
        after = snapshot()
        for table, rows in before.items():
            assert all(row in after[table] for row in rows)


def test_documented_valid_fixture_imports_and_invalid_fixture_is_atomic(db_app, caplog):
    runner = db_app.test_cli_runner()
    valid = runner.invoke(args=["realm-import", str(FIXTURES / "valid-realm.json")])
    assert valid.exit_code == 0, valid.output
    with db_app.app_context():
        before = snapshot()
        browser = db.session.scalar(select(Client).where(Client.client_id == "example-browser"))
        assert browser.pkce_policy == "S256"
        assert browser.redirect_uris == ["http://127.0.0.1:8080/callback"]
    invalid = runner.invoke(args=["realm-import", str(FIXTURES / "invalid-secrets.json")])
    assert invalid.exit_code != 0 and "$.clients[0].secret" in invalid.output
    assert "DO-NOT-USE-PASSWORD" not in invalid.output + caplog.text
    assert "DO-NOT-USE-SECRET" not in invalid.output + caplog.text
    with db_app.app_context():
        assert snapshot() == before
