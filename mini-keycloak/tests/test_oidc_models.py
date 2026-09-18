from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from mini_keycloak import models
from mini_keycloak.extensions import db


def model(name):
    assert hasattr(models, name), f"Missing protocol model: {name}"
    return getattr(models, name)


def identity_records():
    realm = models.Realm(name="oidc-test")
    db.session.add(realm)
    db.session.flush()
    client = models.Client(realm_id=realm.id, client_id="browser")
    user = models.User(realm_id=realm.id, username="alice", username_normalized="alice")
    db.session.add_all([client, user])
    db.session.flush()
    return realm, client, user


def session_record():
    session_type = model("UserSession")
    realm, client, user = identity_records()
    now = datetime.now(timezone.utc)
    session = session_type(
        realm_id=realm.id, client_id=client.id, user_id=user.id,
        idle_expires_at=now + timedelta(minutes=30),
        max_expires_at=now + timedelta(hours=10),
    )
    db.session.add(session)
    db.session.flush()
    return session


def test_client_protocol_defaults_and_realm_overrides_persist(db_app):
    with db_app.app_context():
        realm, client, _ = identity_records()
        assert getattr(client, "pkce_policy", None) == "S256"
        assert client.default_scopes == ["openid", "profile", "email"]
        assert client.optional_scopes == []
        assert client.post_logout_redirect_uris == []
        realm.issuer_override = "https://issuer.test/realms/custom"
        for name in ("access_token", "authorization_code", "refresh_token", "sso_idle", "sso_max"):
            field = name + "_lifetime_seconds"
            assert getattr(realm, field) is None
            setattr(realm, field, 123)
        db.session.commit()
        db.session.expire_all()
        assert realm.issuer_override == "https://issuer.test/realms/custom"
        for name in ("access_token", "authorization_code", "refresh_token", "sso_idle", "sso_max"):
            assert getattr(realm, name + "_lifetime_seconds") == 123


def test_authentication_request_parameters_round_trip(db_app):
    with db_app.app_context():
        realm, client, _ = identity_records()
        columns = models.AuthenticationSession.__table__.columns
        assert {"response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"} <= set(columns.keys())
        auth = models.AuthenticationSession(
            tab_id="opaque-tab", realm_id=realm.id, client_id=client.id,
            redirect_uri="https://client.test/callback", current_execution="login",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            response_type="code", scope="openid email", state="opaque-state",
            nonce="opaque-nonce", code_challenge="challenge", code_challenge_method="S256",
        )
        db.session.add(auth)
        db.session.commit()
        db.session.expire_all()
        assert (auth.response_type, auth.scope, auth.state, auth.nonce, auth.code_challenge, auth.code_challenge_method) == (
            "code", "openid email", "opaque-state", "opaque-nonce", "challenge", "S256"
        )


def test_user_session_opaque_ids_utc_dates_and_revocation_persist(db_app):
    with db_app.app_context():
        session = session_record()
        assert UUID(session.id).version == 4
        assert session.sid and session.sid != session.id
        assert session.revoked_at is None
        db.session.commit()
        db.session.expire_all()
        for name in ("created_at", "auth_time", "last_refresh_at", "idle_expires_at", "max_expires_at"):
            assert getattr(session, name).utcoffset() == timedelta(0)
        revoked = datetime.now(timezone.utc)
        session.revoked_at = revoked
        db.session.commit()
        assert session.revoked_at == revoked


@pytest.mark.parametrize("name, field", [("AuthorizationCode", "code_hash"), ("RefreshToken", "token_hash")])
def test_protocol_handles_persist_only_unique_sha256_hashes(db_app, name, field):
    with db_app.app_context():
        artifact = model(name)
        session = session_record()
        digest = sha256(b"opaque-secret-identifier").hexdigest()
        values = dict(realm_id=session.realm_id, client_id=session.client_id,
                      user_id=session.user_id, user_session_id=session.id,
                      scope="openid email", expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
        values[field] = digest
        if name == "AuthorizationCode":
            values.update(redirect_uri="https://client.test/callback", nonce="nonce",
                          code_challenge="challenge", code_challenge_method="S256")
        else:
            values.update(family_id="opaque-family", generation=0)
        record = artifact(**values)
        db.session.add(record)
        db.session.commit()
        assert UUID(record.id).version == 4
        assert getattr(record, field) == digest
        assert record.created_at.utcoffset() == timedelta(0)
        assert record.expires_at.utcoffset() == timedelta(0)
        assert not ({"code", "token", "raw_code", "raw_token"} & set(artifact.__table__.columns.keys()))
        row = db.session.execute(text(f"SELECT * FROM {artifact.__tablename__}")).first()
        assert "opaque-secret-identifier" not in str(row)
        db.session.add(artifact(**values))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


@pytest.mark.parametrize("name, field", [("AuthorizationCode", "code_hash"), ("RefreshToken", "token_hash")])
@pytest.mark.parametrize("value", ["raw-secret", "g" * 64, "A" * 64])
def test_protocol_hash_fields_reject_non_sha256_values(name, field, value):
    artifact = model(name)
    with pytest.raises(ValueError, match="SHA-256"):
        artifact(**{field: value})


def test_refresh_rotation_and_code_consumption_state_persist(db_app):
    with db_app.app_context():
        refresh_type = model("RefreshToken")
        code_type = model("AuthorizationCode")
        session = session_record()
        now = datetime.now(timezone.utc)
        common = dict(realm_id=session.realm_id, client_id=session.client_id,
                      user_id=session.user_id, user_session_id=session.id,
                      scope="openid", expires_at=now + timedelta(minutes=5))
        replacement = refresh_type(**common, token_hash="b" * 64, family_id="family", generation=1)
        db.session.add(replacement)
        db.session.flush()
        previous = refresh_type(**common, token_hash="a" * 64, family_id="family", generation=0,
                                used_at=now, revoked_at=now, replaced_by_id=replacement.id)
        code = code_type(**common, code_hash="c" * 64, redirect_uri="https://client.test", consumed_at=now)
        db.session.add_all([previous, code])
        db.session.commit()
        db.session.expire_all()
        assert previous.replaced_by_id == replacement.id
        assert previous.used_at == previous.revoked_at == code.consumed_at == now


def test_realm_key_public_identifier_is_unique_within_realm(db_app):
    with db_app.app_context():
        key_type = model("RealmKey")
        realm, _, _ = identity_records()
        other = models.Realm(name="other")
        db.session.add(other)
        db.session.flush()
        values = dict(kid="public-kid", algorithm="RS256", encrypted_private_pem="encrypted",
                      public_jwk={"kty": "RSA", "kid": "public-kid", "n": "public", "e": "AQAB"})
        key = key_type(realm_id=realm.id, **values)
        db.session.add_all([key, key_type(realm_id=other.id, **values)])
        db.session.commit()
        assert UUID(key.id).version == 4
        assert key.active is True
        assert key.activated_at.utcoffset() == timedelta(0)
        assert key.deactivated_at is None
        db.session.add(key_type(realm_id=realm.id, **values))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_security_event_details_and_optional_relationships_persist(db_app):
    with db_app.app_context():
        event_type = model("SecurityEvent")
        realm, client, user = identity_records()
        event = event_type(realm_id=realm.id, client_id=client.id, user_id=user.id,
                           event_type="LOGIN_ERROR", error="invalid_credentials",
                           source_address="127.0.0.1", details={"grant_type": "password"})
        db.session.add(event)
        db.session.commit()
        db.session.expire_all()
        assert UUID(event.id).version == 4
        assert event.details == {"grant_type": "password"}
        assert event.created_at.utcoffset() == timedelta(0)
        assert event.user_session_id is None


@pytest.mark.parametrize("name", ["UserSession", "AuthorizationCode", "RefreshToken", "RealmKey", "SecurityEvent"])
def test_protocol_tables_have_validation_indexes_and_foreign_keys(db_app, name):
    with db_app.app_context():
        table = model(name).__table__
        inspector = inspect(db.engine)
        foreign_keys = {column for fk in inspector.get_foreign_keys(table.name) for column in fk["constrained_columns"]}
        assert "realm_id" in foreign_keys
        indexes = {tuple(index["column_names"]) for index in inspector.get_indexes(table.name)}
        assert ("realm_id",) in indexes
        if name != "RealmKey":
            assert {"client_id", "user_id"} <= foreign_keys
        if name in {"AuthorizationCode", "RefreshToken"}:
            assert "user_session_id" in foreign_keys
            assert ("expires_at",) in indexes
        if name == "RefreshToken":
            assert "replaced_by_id" in foreign_keys
            assert ("family_id",) in indexes


def test_user_session_sid_is_unique(db_app):
    with db_app.app_context():
        first = session_record()
        duplicate = model("UserSession")(
            realm_id=first.realm_id, client_id=first.client_id, user_id=first.user_id,
            sid=first.sid, idle_expires_at=first.idle_expires_at, max_expires_at=first.max_expires_at,
        )
        db.session.add(duplicate)
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
