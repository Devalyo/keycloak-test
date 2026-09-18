import json
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from mini_keycloak.extensions import db
from mini_keycloak.models import Realm, RealmKey, User
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.keys import RealmKeyService


PASSWORD = "cli-password-sentinel-783!"
SECRET = "cli-secret-sentinel-931!"


def document():
    return {
        "realm": "imported", "displayName": "Imported realm",
        "clients": [{"clientId": "browser", "redirectUris": ["https://app.example/callback"]},
                    {"clientId": "backend", "publicClient": False, "secret": SECRET}],
        "users": [{"username": "alice", "credentials": [{"type": "password", "value": PASSWORD}]}],
    }


def write_document(tmp_path, data):
    path = tmp_path / "realm.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def snapshot():
    return {table.name: sorted((tuple(repr(value) for value in row)
                               for row in db.session.execute(select(table))), key=repr)
            for table in db.metadata.sorted_tables}


def assert_safe_failure(result, caplog):
    assert result.exit_code != 0
    assert "Error:" in result.output
    assert "No such command" not in result.output
    assert "Traceback" not in result.output
    for secret in (PASSWORD, SECRET):
        assert secret not in result.output + caplog.text + repr(result.exception)


def test_cli_import_creates_hashed_identities_and_one_key(db_app, tmp_path):
    path = write_document(tmp_path, document())
    result = db_app.test_cli_runner().invoke(args=["realm-import", str(path)])
    assert result.exit_code == 0, result.output
    assert "clients=2" in result.output and "users=1" in result.output
    assert len(result.output.splitlines()) == 1
    with db_app.app_context():
        realm = db.session.scalars(select(Realm)).one()
        assert realm.name == "imported"
        user = db.session.scalars(select(User)).one()
        assert IdentityRepository(db.session).password_matches(user, PASSWORD)
        assert db.session.scalars(select(RealmKey)).one().active
        assert PASSWORD not in repr(snapshot()) and SECRET not in repr(snapshot())


def test_duplicate_requires_explicit_non_destructive_update(db_app, tmp_path, caplog):
    path = write_document(tmp_path, document())
    runner = db_app.test_cli_runner()
    assert runner.invoke(args=["realm-import", str(path)]).exit_code == 0
    with db_app.app_context():
        before = snapshot()
    write_document(tmp_path, {"realm": "IMPORTED", "displayName": "Changed"})
    result = runner.invoke(args=["realm-import", str(path)])
    assert_safe_failure(result, caplog)
    assert "--update" in result.output
    with db_app.app_context():
        assert snapshot() == before
    result = runner.invoke(args=["realm-import", str(path), "--update"])
    assert result.exit_code == 0, result.output
    with db_app.app_context():
        assert db.session.scalars(select(Realm)).one().display_name == "Changed"
        after = snapshot()
        for table in before.keys() - {"realms"}:
            assert after[table] == before[table]


def test_warnings_are_sorted_paths_without_values(db_app, tmp_path, caplog):
    data = document()
    data.update({"zUnsupported": SECRET, "aUnsupported": PASSWORD})
    data["clients"][0]["protocolMappers"] = [{"secret": SECRET}]
    result = db_app.test_cli_runner().invoke(args=["realm-import", str(write_document(tmp_path, data))])
    assert result.exit_code == 0, result.output
    warnings = [line for line in result.output.splitlines() if line.startswith("Warning:")]
    assert len(warnings) == 3 and warnings == sorted(warnings)
    assert "$.aUnsupported" in warnings[0]
    assert "$.clients[0].protocolMappers" in warnings[1]
    assert "$.zUnsupported" in warnings[2]
    assert PASSWORD not in result.output + caplog.text
    assert SECRET not in result.output + caplog.text


@pytest.mark.parametrize("contents", [
    b"", b"[]", b"null", b'{"realm":"imported"} trailing', b"\xff",
    b'{"realm":"imported", "realm":"other"}',
    b'{"realm":"imported","users":[{"username":"alice","username":"bob"}]}',
    b'{"realm":"imported","users":[{"username":"alice","credentials":[{"type":"password","value":"one","value":"two"}]}]}',
    b'{"realm":"imported","enabled":NaN}',
    b'{"realm":"imported","enabled":Infinity}',
    b"[" * 2000 + b"]" * 2000,
    b" " * (2 * 1024 * 1024 + 1),
], ids=["empty", "array", "null", "trailing", "utf8", "duplicate-realm", "duplicate-user",
        "duplicate-credential", "nan", "infinity", "deep", "oversized"])
def test_invalid_files_fail_without_mutation(db_app, tmp_path, caplog, contents):
    path = tmp_path / "realm.json"
    path.write_bytes(contents)
    result = db_app.test_cli_runner().invoke(args=["realm-import", str(path)])
    assert_safe_failure(result, caplog)
    with db_app.app_context():
        assert not any(snapshot().values())


@pytest.mark.parametrize("kind", ["missing", "directory", "unreadable"])
def test_io_errors_do_not_echo_path_or_exception(db_app, tmp_path, caplog, monkeypatch, kind):
    path = tmp_path / SECRET
    if kind == "directory":
        path.mkdir()
    elif kind == "unreadable":
        path.write_text("{}")
        original = Path.open

        def denied(self, *args, **kwargs):
            if self == path:
                raise PermissionError(SECRET)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", denied)
    result = db_app.test_cli_runner().invoke(args=["realm-import", str(path)])
    assert_safe_failure(result, caplog)


def test_validation_reports_paths_before_any_mutation(db_app, tmp_path, caplog):
    data = document()
    data["users"].append({"username": "ALICE"})
    data["enabled"] = SECRET
    result = db_app.test_cli_runner().invoke(args=["realm-import", str(write_document(tmp_path, data))])
    assert_safe_failure(result, caplog)
    assert "$.enabled" in result.output and "$.users[1].username" in result.output
    with db_app.app_context():
        assert not any(snapshot().values())


@pytest.mark.parametrize("failure", ["crypto", "commit"])
def test_internal_failures_roll_back_and_hide_exception_details(db_app, tmp_path, caplog, monkeypatch, failure):
    path = write_document(tmp_path, document())

    def fail(*args, **kwargs):
        raise OperationalError(SECRET, {"password": PASSWORD}, RuntimeError(PASSWORD))

    with db_app.app_context():
        if failure == "crypto":
            monkeypatch.setattr(RealmKeyService, "ensure_active_key", fail)
        else:
            monkeypatch.setattr(db.session, "commit", fail)
        result = db_app.test_cli_runner().invoke(args=["realm-import", str(path)])
        assert_safe_failure(result, caplog)
        assert not any(snapshot().values())
        assert db.session.scalar(select(Realm)) is None


def test_failed_update_commit_restores_existing_data(db_app, tmp_path, caplog, monkeypatch):
    path = write_document(tmp_path, document())
    runner = db_app.test_cli_runner()
    assert runner.invoke(args=["realm-import", str(path)]).exit_code == 0
    write_document(tmp_path, {"realm": "imported", "displayName": "Changed", "clients": [{"clientId": "new"}]})
    with db_app.app_context():
        before = snapshot()

        def fail():
            raise OperationalError(SECRET, {}, RuntimeError(PASSWORD))

        monkeypatch.setattr(db.session, "commit", fail)
        result = runner.invoke(args=["realm-import", str(path), "--update"])
        assert_safe_failure(result, caplog)
        assert snapshot() == before


@pytest.mark.parametrize("overflow", [False, True])
def test_document_byte_limit_accepts_exact_boundary_only(db_app, tmp_path, overflow, caplog):
    path = tmp_path / "realm.json"
    payload = b'{"realm":"boundary"}'
    path.write_bytes(payload + b" " * (2 * 1024 * 1024 - len(payload) + overflow))
    result = db_app.test_cli_runner().invoke(args=["realm-import", str(path)])
    if overflow:
        assert_safe_failure(result, caplog)
    else:
        assert result.exit_code == 0, result.output
    with db_app.app_context():
        assert (db.session.scalar(select(Realm)) is None) is overflow
