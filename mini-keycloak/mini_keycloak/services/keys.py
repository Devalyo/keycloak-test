import base64
import secrets
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import Session

from mini_keycloak.models import RealmKey
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.keys import RealmKeyRepository
from mini_keycloak.security.key_encryption import encrypt_private_pem


def _base64url_integer(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class RealmKeyRealmUnavailable(ValueError):
    """The requested realm is missing or disabled for key administration."""


@dataclass(frozen=True)
class RealmKeyMetadata:
    kid: str
    algorithm: str
    status: str
    created_at: datetime
    activated_at: datetime
    deactivated_at: datetime | None

    @classmethod
    def from_key(cls, key: RealmKey) -> "RealmKeyMetadata":
        return cls(key.kid, key.algorithm, "active" if key.active else "retained",
                   key.created_at, key.activated_at, key.deactivated_at)


class RealmKeyService:
    def __init__(self, session: Session, master_secret: str) -> None:
        self.repository = RealmKeyRepository(session)
        self._master_secret = master_secret

    def ensure_active_key(self, realm_id: str) -> RealmKey:
        """Create a key inside the caller's transaction, preserving an active key."""
        self.repository.lock_realm(realm_id)
        existing = self.repository.get_active(realm_id)
        if existing is not None:
            return existing
        return self.repository.add(self._generate_key(realm_id))

    def list_keys(self, realm_id: str) -> list[RealmKeyMetadata]:
        """Return only administrative metadata, never stored key material."""
        if not self.repository.realm_enabled(realm_id):
            raise RealmKeyRealmUnavailable("Realm not found or disabled")
        return [RealmKeyMetadata.from_key(key)
                for key in self.repository.list_verification_keys(realm_id)]

    def rotate_active_key(self, realm_id: str) -> RealmKeyMetadata:
        """Rotate under a realm lock; the caller owns commit and rollback."""
        try:
            enabled = self.repository.lock_realm(realm_id)
        except NoResultFound:
            raise RealmKeyRealmUnavailable("Realm not found or disabled") from None
        if not enabled:
            raise RealmKeyRealmUnavailable("Realm not found or disabled")
        replacement = self._generate_key(realm_id)
        self.repository.deactivate_active(realm_id, utc_now())
        return RealmKeyMetadata.from_key(self.repository.add(replacement))

    def _generate_key(self, realm_id: str) -> RealmKey:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public = private_key.public_key().public_numbers()
        kid = secrets.token_urlsafe(24)
        return RealmKey(
            realm_id=realm_id,
            kid=kid,
            algorithm="RS256",
            encrypted_private_pem=encrypt_private_pem(private_pem, self._master_secret),
            public_jwk={
                "kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig",
                "n": _base64url_integer(public.n), "e": _base64url_integer(public.e),
            },
            active=True,
        )

    def public_jwks(self, realm_id: str) -> dict:
        # Explicitly project public members even if stored JSON is contaminated.
        return {"keys": [
            {"kid": key.kid, "kty": "RSA", "alg": "RS256", "use": "sig",
             "n": key.public_jwk["n"], "e": key.public_jwk["e"]}
            for key in self.repository.list_verification_keys(realm_id)
        ]}
