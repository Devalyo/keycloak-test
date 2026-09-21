import base64
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import select, text

from mini_keycloak.extensions import db
from mini_keycloak.models import Realm, RealmKey
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.bootstrap import ensure_demo_realm


def test_bootstrap_preserves_one_active_key_across_transactions(db_app):
    with db_app.app_context():
        realm = ensure_demo_realm(db.session)
        db.session.commit()
        keys = db.session.scalars(select(RealmKey).where(RealmKey.realm_id == realm.id)).all()
        assert len(keys) == 1
        first = (keys[0].kid, keys[0].encrypted_private_pem)
        assert keys[0].active and keys[0].algorithm == "RS256"
        ensure_demo_realm(db.session)
        db.session.commit()
        db.session.expire_all()
        keys = db.session.scalars(select(RealmKey).where(RealmKey.realm_id == realm.id)).all()
        assert len(keys) == 1
        assert (keys[0].kid, keys[0].encrypted_private_pem) == first


def test_bootstrap_adds_key_to_existing_realm_without_replacing_credentials(db_app):
    with db_app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.create_realm("demo")
        user = repository.create_user(realm.id, "existing", None, "ExistingPassword!")
        db.session.commit()
        ensure_demo_realm(db.session)
        db.session.commit()
        assert db.session.scalar(select(RealmKey).where(RealmKey.realm_id == realm.id)) is not None
        assert repository.password_matches(user, "ExistingPassword!")


def test_private_key_is_encrypted_and_matches_public_jwk(db_app):
    from mini_keycloak.security.key_encryption import decrypt_private_pem

    db_app.config["OIDC_KEY_ENCRYPTION_SECRET"] = "test-master-secret"
    with db_app.app_context():
        ensure_demo_realm(db.session)
        db.session.commit()
        stored = db.session.execute(text("SELECT encrypted_private_pem FROM realm_keys")).scalar_one()
        assert "PRIVATE KEY" not in stored
        private_pem = decrypt_private_pem(stored, "test-master-secret")
        assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        key = serialization.load_pem_private_key(private_pem, password=None)
        assert isinstance(key, rsa.RSAPrivateKey) and key.key_size == 2048
        record = db.session.scalar(select(RealmKey))
        jwk = record.public_jwk
        decode = lambda value: int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")
        public = rsa.RSAPublicNumbers(decode(jwk["e"]), decode(jwk["n"])).public_key()
        signature = key.sign(b"realm-key-check", padding.PKCS1v15(), hashes.SHA256())
        public.verify(signature, b"realm-key-check", padding.PKCS1v15(), hashes.SHA256())
        with pytest.raises(InvalidSignature):
            public.verify(signature, b"different-message", padding.PKCS1v15(), hashes.SHA256())
        assert set(jwk) == {"kid", "kty", "alg", "use", "n", "e"}
        assert jwk["kid"] == record.kid
        assert (jwk["kty"], jwk["alg"], jwk["use"], jwk["e"]) == ("RSA", "RS256", "sig", "AQAB")
        assert "=" not in jwk["n"]
        with pytest.raises(InvalidToken):
            decrypt_private_pem(stored, "wrong-master-secret")
        damaged = bytearray(base64.urlsafe_b64decode(stored))
        damaged[-1] ^= 1
        with pytest.raises(InvalidToken):
            decrypt_private_pem(base64.urlsafe_b64encode(damaged).decode(), "test-master-secret")


@pytest.mark.parametrize("secret", ["", None])
def test_key_encryption_rejects_missing_master_secret(secret):
    from mini_keycloak.security.key_encryption import encrypt_private_pem

    with pytest.raises(ValueError, match="secret"):
        encrypt_private_pem(b"private-pem", secret)


def test_each_realm_gets_its_own_stable_key_and_retains_old_keys(db_app):
    from mini_keycloak.services.keys import RealmKeyService

    with db_app.app_context():
        repository = IdentityRepository(db.session)
        first = repository.create_realm("first")
        second = repository.create_realm("second")
        service = RealmKeyService(db.session, db_app.config["OIDC_KEY_ENCRYPTION_SECRET"])
        first_key = service.ensure_active_key(first.id)
        second_key = service.ensure_active_key(second.id)
        assert first_key.kid != second_key.kid
        assert first_key.public_jwk["n"] != second_key.public_jwk["n"]
        first_key.active = False
        db.session.commit()
        replacement = service.ensure_active_key(first.id)
        db.session.commit()
        assert replacement.kid != first_key.kid
        assert service.ensure_active_key(first.id).kid == replacement.kid
        assert service.ensure_active_key(second.id).kid == second_key.kid
        assert len(db.session.scalars(select(RealmKey).where(RealmKey.realm_id == first.id)).all()) == 2


def test_concurrent_key_initialization_keeps_one_active_key(db_app):
    from mini_keycloak.services.keys import RealmKeyService

    with db_app.app_context():
        realm = IdentityRepository(db.session).create_realm("concurrent")
        realm_id = realm.id
        db.session.commit()
    start = Barrier(4)

    def initialize():
        with db_app.app_context():
            start.wait(timeout=5)
            key = RealmKeyService(db.session, db_app.config["OIDC_KEY_ENCRYPTION_SECRET"]).ensure_active_key(realm_id)
            kid = key.kid
            db.session.commit()
            return kid

    with ThreadPoolExecutor(max_workers=4) as executor:
        kids = list(executor.map(lambda _: initialize(), range(4)))
    assert len(set(kids)) == 1
    with db_app.app_context():
        assert len(db.session.scalars(select(RealmKey).where(RealmKey.realm_id == realm_id)).all()) == 1


def test_rotation_returns_safe_metadata_and_respects_caller_rollback(app):
    from dataclasses import asdict
    from mini_keycloak.services.keys import RealmKeyService

    with app.app_context():
        original = db.session.scalar(select(RealmKey))
        realm_id, old_kid, encrypted = original.realm_id, original.kid, original.encrypted_private_pem
        service = RealmKeyService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET'])
        replacement = service.rotate_active_key(realm_id)
        assert replacement.kid != old_kid
        assert set(asdict(replacement)) == {'kid', 'algorithm', 'status', 'created_at', 'activated_at', 'deactivated_at'}
        assert replacement.status == 'active' and replacement.algorithm == 'RS256'
        assert replacement.created_at is not None and replacement.activated_at is not None
        assert replacement.deactivated_at is None
        metadata = service.list_keys(realm_id)
        assert {key.status for key in metadata} == {'active', 'retained'}
        assert encrypted not in repr(metadata)
        assert all('encrypted_private_pem' not in asdict(key) and 'public_jwk' not in asdict(key) for key in metadata)
        db.session.rollback()
        key = db.session.scalars(select(RealmKey)).one()
        assert key.kid == old_kid and key.active and key.deactivated_at is None


def test_concurrent_rotation_retains_every_key_and_one_active_key(app):
    from mini_keycloak.services.keys import RealmKeyService

    with app.app_context():
        original = db.session.scalar(select(RealmKey))
        realm_id, old_kid = original.realm_id, original.kid
    start = Barrier(4)

    def rotate():
        with app.app_context():
            # Keep the old ORM instance loaded to exercise stale identity maps.
            old_key = db.session.scalar(select(RealmKey).where(RealmKey.kid == old_kid))
            start.wait(timeout=5)
            key = RealmKeyService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET']).rotate_active_key(realm_id)
            assert old_key.active is False
            db.session.commit()
            return key.kid

    with ThreadPoolExecutor(max_workers=4) as executor:
        kids = list(executor.map(lambda _: rotate(), range(4)))
    assert len(set(kids)) == 4
    with app.app_context():
        keys = db.session.scalars(select(RealmKey).where(RealmKey.realm_id == realm_id)).all()
        assert {key.kid for key in keys} == {old_kid, *kids}
        assert sum(key.active for key in keys) == 1
        assert all(key.deactivated_at is not None for key in keys if not key.active)


def test_rotation_does_not_change_another_realms_key(app):
    from mini_keycloak.services.keys import RealmKeyService

    with app.app_context():
        existing = db.session.scalar(select(RealmKey))
        other = IdentityRepository(db.session).create_realm('other')
        service = RealmKeyService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET'])
        other_key = service.ensure_active_key(other.id)
        other_kid = other_key.kid
        db.session.commit()
        service.rotate_active_key(existing.realm_id)
        db.session.commit()
        assert other_key.kid == other_kid and other_key.active and other_key.deactivated_at is None


@pytest.mark.parametrize('operation', ['list_keys', 'rotate_active_key'])
@pytest.mark.parametrize('state', ['unknown', 'disabled'])
def test_key_service_rejects_unavailable_realms(app, operation, state):
    from mini_keycloak.services.keys import RealmKeyService

    with app.app_context():
        realm = db.session.scalar(select(Realm))
        realm_id = realm.id
        before = db.session.scalar(select(RealmKey)).kid
        if state == 'disabled':
            realm.enabled = False
            db.session.commit()
        service = RealmKeyService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET'])
        with pytest.raises(ValueError, match='not found or disabled'):
            getattr(service, operation)(realm_id if state == 'disabled' else 'missing')
        db.session.rollback()
        key = db.session.scalars(select(RealmKey)).one()
        assert key.kid == before and key.active and key.deactivated_at is None
