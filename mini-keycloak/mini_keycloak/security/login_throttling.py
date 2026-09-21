"""Persistent failure accounting for ordinary credential checks only."""
from datetime import timedelta
import hmac
from ipaddress import ip_address

from sqlalchemy import case, delete, or_, select
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from mini_keycloak.models import LoginFailureBucket
from mini_keycloak.models.authentication import validate_sha256
from mini_keycloak.models.identity import new_id, utc_now
from mini_keycloak.oidc.errors import InvalidGrant
from mini_keycloak.repositories.identity import IdentityRepository


class CredentialFailure(InvalidGrant):
    """Carry only a private bucket across the rejected grant's rollback."""

    def __init__(self, realm_id, bucket_hash, *, blocked=False):
        super().__init__()
        self.realm_id = realm_id
        self.bucket_hash = bucket_hash
        self.blocked = blocked


class LoginThrottle:
    """Caller owns transactions; a conflict update serializes each bucket.

    A block lasts a fixed interval from the threshold failure. Attempts during
    that interval cannot increment the count or prolong it. After either the
    counting window or a previous block expires, the next failure starts over.
    """

    def __init__(self, session, *, secret, threshold, window_seconds, lock_seconds):
        self.session = session
        self.secret = secret.encode('utf-8') if isinstance(secret, str) else secret
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.lock = timedelta(seconds=lock_seconds)

    @classmethod
    def from_config(cls, session, config):
        return cls(session, secret=config['SECRET_KEY'], threshold=config['LOGIN_FAILURE_THRESHOLD'],
                   window_seconds=config['LOGIN_FAILURE_WINDOW_SECONDS'],
                   lock_seconds=config['LOGIN_LOCK_SECONDS'])

    def bucket_hash(self, realm_id, identifier, source_address):
        try:
            # Zone identifiers are local interface names, not canonical peers.
            address = str(ip_address(source_address)) if source_address and '%' not in source_address else '<unknown>'
        except ValueError:
            address = '<unknown>'
        digest = hmac.new(self.secret, b'mini-keycloak/login-throttle/v1\0', 'sha256')
        for value in (realm_id, identifier.strip().casefold(), address):
            encoded = value.encode('utf-8')
            digest.update(len(encoded).to_bytes(8, 'big'))
            digest.update(encoded)
        return digest.hexdigest()

    def is_blocked(self, realm_id, bucket_hash, *, now=None):
        now = now or utc_now()
        return self.session.scalar(select(LoginFailureBucket.id).where(
            LoginFailureBucket.realm_id == realm_id, LoginFailureBucket.bucket_hash == bucket_hash,
            LoginFailureBucket.blocked_until > now)) is not None

    def record_failure(self, realm_id, bucket_hash, *, now=None):
        now = now or utc_now()
        bucket_hash = validate_sha256(bucket_hash)
        table = LoginFailureBucket.__table__
        dialect = self.session.get_bind().dialect.name
        insert = {'sqlite': sqlite_insert, 'postgresql': postgres_insert}.get(dialect)
        if insert is None:
            raise RuntimeError('Unsupported login throttling database')
        reset = or_(table.c.first_failure_at <= now - self.window,
                    table.c.blocked_until <= now)
        count = case((reset, 1), else_=table.c.failure_count + 1)
        statement = insert(table).values(id=new_id(), realm_id=realm_id, bucket_hash=bucket_hash,
            failure_count=1, first_failure_at=now, last_failure_at=now,
            blocked_until=now + self.lock if self.threshold == 1 else None,
            expires_at=now + max(self.window, self.lock))
        statement = statement.on_conflict_do_update(
            index_elements=[table.c.realm_id, table.c.bucket_hash],
            set_={'failure_count': count,
                  'first_failure_at': case((reset, now), else_=table.c.first_failure_at),
                  'last_failure_at': now,
                  'blocked_until': case((count >= self.threshold, now + self.lock), else_=None),
                  'expires_at': now + max(self.window, self.lock)},
            where=or_(table.c.blocked_until.is_(None), table.c.blocked_until <= now))
        self.session.execute(statement)

    def clear(self, realm_id, bucket_hash):
        self.session.execute(delete(LoginFailureBucket).where(
            LoginFailureBucket.realm_id == realm_id, LoginFailureBucket.bucket_hash == bucket_hash))

    def authenticate(self, realm_id, identifier, password, *, source_address, dummy_hash):
        """Verify credentials without committing; no raw input is retained."""
        bucket_hash = self.bucket_hash(realm_id, identifier, source_address)
        identities = IdentityRepository(self.session)
        if self.is_blocked(realm_id, bucket_hash):
            identities.passwords.verify(dummy_hash, password)
            raise CredentialFailure(realm_id, bucket_hash, blocked=True)
        user = identities.find_user(realm_id, identifier)
        if user is None:
            identities.passwords.verify(dummy_hash, password)
            valid = False
        else:
            valid = identities.password_matches(user, password)
        if not valid:
            raise CredentialFailure(realm_id, bucket_hash)
        return user, bucket_hash
