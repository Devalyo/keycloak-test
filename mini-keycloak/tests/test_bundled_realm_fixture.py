from datetime import timedelta
from importlib.resources import files
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import zipfile

import pytest
from sqlalchemy import select

from mini_keycloak.app import create_app
from mini_keycloak.extensions import db
from mini_keycloak.import_export.validation import validate_realm_import
from mini_keycloak.models import Client, Credential, User, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.bootstrap import ensure_demo_realm
from mini_keycloak.services.clients import ClientService
from mini_keycloak.services.realm_import import RealmImportService


def snapshot():
    return {table.name: sorted((tuple(repr(value) for value in row)
                               for row in db.session.execute(select(table))), key=repr)
            for table in db.metadata.sorted_tables}


def test_packaged_fixture_imports_the_bundled_identity_contract(db_app, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fixture = files("mini_keycloak.import_export").joinpath("fixtures/demo-realm.json")
    result = validate_realm_import(json.loads(fixture.read_text(encoding="utf-8")))
    assert result.warnings == ()
    with db_app.app_context():
        realm = RealmImportService(db.session, db_app.config["OIDC_KEY_ENCRYPTION_SECRET"]).import_realm(result.value)
        db.session.commit()
        assert realm.name == "demo" and realm.password_grant_enabled
        client = db.session.scalars(select(Client)).one()
        assert client.client_id == "demo-app" and client.public_client
        assert client.redirect_uris == ["http://localhost:9999/callback"]
        assert client.pkce_policy == "optional" and client.direct_access_grants_enabled
        user = db.session.scalars(select(User)).one()
        assert user.username == "demo-user" and user.email == "demo-user@example.test"
        assert IdentityRepository(db.session).password_matches(user, "DemoPassw0rd!")


@pytest.mark.parametrize("missing", ["client", "user", "both"])
def test_bootstrap_repairs_missing_bundled_entities(db_app, missing):
    with db_app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.create_realm("demo", display_name="Operator name")
        if missing == "user":
            repository.create_client(realm.id, "demo-app", redirect_uris=["https://operator.example/callback"],
                                     direct_access_grants_enabled=True)
        if missing == "client":
            repository.create_user(realm.id, "demo-user", "changed@example.test", "Changed-pass-123!")
        db.session.commit()
        realm_id = realm.id
        ensure_demo_realm(db.session)
        db.session.commit()
        assert repository.get_client(realm_id, "demo-app") is not None
        assert repository.find_user(realm_id, "demo-user") is not None
        assert realm.display_name == "Operator name" and realm.id == realm_id
        if missing in {"user", "both"}:
            assert repository.password_matches(repository.find_user(realm_id, "demo-user"), "DemoPassw0rd!")
    if missing in {"user", "both"}:
        response = db_app.test_client().post("/realms/demo/protocol/openid-connect/token", data={
            "grant_type": "password", "client_id": "demo-app", "username": "demo-user",
            "password": "DemoPassw0rd!",
        })
        assert response.status_code == 200
        assert response.json["access_token"]


def test_bootstrap_preserves_absent_password_of_existing_bundled_user(app):
    with app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.get_realm("demo")
        user = repository.find_user(realm.id, "demo-user")
        credential = db.session.scalar(select(Credential).where(Credential.user_id == user.id))
        db.session.delete(credential)
        db.session.commit()
        before = snapshot()
        ensure_demo_realm(db.session)
        db.session.commit()
        assert snapshot() == before
        assert not repository.password_matches(user, "DemoPassw0rd!")


def test_bootstrap_preserves_absent_secret_of_existing_confidential_client(app):
    with app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.get_realm("demo")
        client = repository.get_client(realm.id, "demo-app")
        client.public_client = False
        client.secret_hash = None
        db.session.commit()
        before = snapshot()
        ensure_demo_realm(db.session)
        db.session.commit()
        assert snapshot() == before
        assert client.secret_hash is None


def test_bootstrap_preserves_operator_data_credentials_keys_and_sessions(app):
    with app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.get_realm("demo")
        client = repository.get_client(realm.id, "demo-app")
        user = repository.find_user(realm.id, "demo-user")
        repository.set_password(user, "Changed-pass-123!")
        realm.display_name = "Operator name"
        realm.enabled = False
        realm.forgot_password_allowed = False
        realm.password_policy = {"length": 18}
        realm.access_token_lifetime_seconds = 73
        realm.password_grant_enabled = False
        client.name = "Operator app"
        client.redirect_uris = ["https://operator.example/callback"]
        client.direct_access_grants_enabled = False
        client.pkce_policy = "S256"
        client.public_client = False
        ClientService(db.session).set_secret(client, "Operator-client-secret-123!")
        user.email = "changed@example.test"
        user.email_normalized = "changed@example.test"
        user.first_name = "Operator"
        user.attributes = {"team": ["ops"]}
        repository.create_client(realm.id, "operator-app", redirect_uris=[])
        repository.create_user(realm.id, "operator", "operator@example.test", "Operator-pass-123!")
        db.session.add(UserSession(realm_id=realm.id, client_id=client.id, user_id=user.id,
                                   idle_expires_at=utc_now() + timedelta(hours=1),
                                   max_expires_at=utc_now() + timedelta(hours=2)))
        db.session.commit()
        preserved = snapshot()
        # These are the two existing bootstrap policy normalizations.
        realm.password_grant_enabled = True
        client.pkce_policy = "optional"
        db.session.commit()
        expected = snapshot()
        realm.password_grant_enabled = False
        client.pkce_policy = "S256"
        db.session.commit()
        assert snapshot() == preserved
        ensure_demo_realm(db.session)
        db.session.commit()
        assert snapshot() == expected
        assert repository.password_matches(user, "Changed-pass-123!")
        assert not repository.password_matches(user, "DemoPassw0rd!")


def test_bootstrap_preserves_normalized_identifier_spellings(app):
    with app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.get_realm("demo")
        client = repository.get_client(realm.id, "demo-app")
        user = repository.find_user(realm.id, "demo-user")
        realm.name = "DEMO"
        client.client_id = "DEMO-APP"
        user.username = "Demo-User"
        db.session.commit()
        before = snapshot()
        ensure_demo_realm(db.session)
        db.session.commit()
        assert snapshot() == before


def test_migrated_database_double_bootstrap_has_identical_rows_and_metadata(tmp_path):
    project = Path(__file__).parents[1]
    database_url = f"sqlite+pysqlite:///{tmp_path / 'migrated.sqlite3'}"
    env = {**os.environ, "MINI_KEYCLOAK_DATABASE_URL": database_url}
    subprocess.run([sys.executable, "-m", "flask", "--app", "mini_keycloak.app", "db", "upgrade"],
                   cwd=project, env=env, check=True, capture_output=True, text=True)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": database_url})
    runner = app.test_cli_runner()
    assert runner.invoke(args=["bootstrap-demo"]).exit_code == 0
    with app.app_context():
        before = snapshot()
    client = app.test_client()
    metadata = client.get("/realms/demo/.well-known/openid-configuration").json
    jwks = client.get("/realms/demo/protocol/openid-connect/certs").json
    assert runner.invoke(args=["bootstrap-demo"]).exit_code == 0
    with app.app_context():
        assert snapshot() == before
    assert client.get("/realms/demo/.well-known/openid-configuration").json == metadata
    assert client.get("/realms/demo/protocol/openid-connect/certs").json == jwks


def test_fixture_is_in_built_wheel_and_sdist_and_loads_outside_source(tmp_path):
    project = Path(__file__).parents[1]
    source = tmp_path / "source"
    source.mkdir()
    shutil.copy2(project / "pyproject.toml", source)
    shutil.copytree(project / "mini_keycloak", source / "mini_keycloak",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    subprocess.run([sys.executable, "-c", "from setuptools.build_meta import build_wheel, build_sdist; "
                    "build_wheel('dist'); build_sdist('dist')"], cwd=source, check=True,
                   capture_output=True, text=True)
    wheel = next((source / "dist").glob("*.whl"))
    sdist = next((source / "dist").glob("*.tar.gz"))
    fixture_name = "mini_keycloak/import_export/fixtures/demo-realm.json"
    with zipfile.ZipFile(wheel) as archive:
        assert fixture_name in archive.namelist()
    with tarfile.open(sdist) as archive:
        assert any(name.endswith("/" + fixture_name) for name in archive.getnames())
    script = ("from importlib.resources import files; import json; "
              "from mini_keycloak.import_export.validation import validate_realm_import; "
              "result = validate_realm_import(json.loads(files('mini_keycloak.import_export')"
              ".joinpath('fixtures/demo-realm.json').read_text())); "
              "assert result.value.name == 'demo'; assert not result.warnings")
    subprocess.run([sys.executable, "-c", script], cwd=tmp_path,
                   env={**os.environ, "PYTHONPATH": str(wheel)}, check=True, capture_output=True, text=True)
