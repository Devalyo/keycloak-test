from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from mini_keycloak.models import AuthorizationCode, RefreshToken, UserSession


class RefreshTokenRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get(self, token_hash: str, realm_id: str, client_id: str) -> RefreshToken | None:
        return self.session.scalar(select(RefreshToken).where(
            RefreshToken.token_hash == token_hash, RefreshToken.realm_id == realm_id,
            RefreshToken.client_id == client_id).execution_options(populate_existing=True))

    def lock_session(self, session_id: str, now: datetime) -> UserSession | None:
        # Serialize all generations on their session, including ancestor reuse
        # racing a descendant rotation. A conditional write works on SQLite and
        # PostgreSQL, where SELECT FOR UPDATE alone would not be portable.
        return self.session.scalar(update(UserSession).where(
            UserSession.id == session_id, UserSession.revoked_at.is_(None),
            UserSession.idle_expires_at > now, UserSession.max_expires_at > now,
        ).values(last_refresh_at=UserSession.last_refresh_at).returning(UserSession)
            .execution_options(populate_existing=True, synchronize_session=False))

    def consume(self, token_id: str, now: datetime) -> RefreshToken | None:
        return self.session.scalar(update(RefreshToken).where(
            RefreshToken.id == token_id, RefreshToken.used_at.is_(None),
            RefreshToken.revoked_at.is_(None), RefreshToken.expires_at > now,
        ).values(used_at=now).returning(RefreshToken)
            .execution_options(populate_existing=True, synchronize_session=False))


class AuthorizationCodeRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, code: AuthorizationCode) -> AuthorizationCode:
        self.session.add(code)
        self.session.flush()
        return code

    def get(self, code_hash: str) -> AuthorizationCode | None:
        return self.session.scalar(select(AuthorizationCode).where(
            AuthorizationCode.code_hash == code_hash).execution_options(populate_existing=True))

    def consume(self, code_id: str, *, realm_id: str, client_id: str,
                redirect_uri: str, now: datetime) -> AuthorizationCode | None:
        # The conditional write is authoritative even if another worker read
        # the same unconsumed row. The caller owns commit of the token transaction.
        return self.session.scalar(update(AuthorizationCode).where(
            AuthorizationCode.id == code_id,
            AuthorizationCode.realm_id == realm_id,
            AuthorizationCode.client_id == client_id,
            AuthorizationCode.redirect_uri == redirect_uri,
            AuthorizationCode.consumed_at.is_(None),
            AuthorizationCode.expires_at > now,
        ).values(consumed_at=now).returning(AuthorizationCode)
            .execution_options(populate_existing=True, synchronize_session=False))
