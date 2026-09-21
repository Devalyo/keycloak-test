from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from mini_keycloak.models import Client, Realm, RefreshToken, User, UserSession


class UserSessionRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, user_session: UserSession) -> UserSession:
        self.session.add(user_session)
        self.session.flush()
        return user_session

    def revoke(self, sid: str, realm_id: str, now: datetime) -> bool:
        # Take the same session write lock used by refresh before touching
        # families: a racing refresh cannot leave an active descendant behind.
        user_session = self.session.scalar(update(UserSession).where(
            UserSession.sid == sid, UserSession.realm_id == realm_id,
        ).values(revoked_at=func.coalesce(UserSession.revoked_at, now)).returning(UserSession)
            .execution_options(populate_existing=True, synchronize_session=False))
        if user_session is None:
            return False
        self.session.execute(update(RefreshToken).where(
            RefreshToken.realm_id == realm_id,
            RefreshToken.user_session_id == user_session.id,
            RefreshToken.revoked_at.is_(None),
        ).values(revoked_at=user_session.revoked_at))
        return True

    def eligible(self, sid: str, realm_id: str, now: datetime) -> UserSession | None:
        return self.session.scalar(
            select(UserSession)
            .join(Realm, Realm.id == UserSession.realm_id)
            .join(User, User.id == UserSession.user_id)
            .join(Client, Client.id == UserSession.client_id)
            .where(
                UserSession.sid == sid,
                UserSession.realm_id == realm_id,
                User.realm_id == realm_id,
                Client.realm_id == realm_id,
                Realm.enabled.is_(True),
                User.enabled.is_(True),
                Client.enabled.is_(True),
                UserSession.revoked_at.is_(None),
                UserSession.idle_expires_at > now,
                UserSession.max_expires_at > now,
            )
        )
