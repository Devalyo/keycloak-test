from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy.orm import Session

from mini_keycloak.models import AuthenticationSession, Client, Realm, User, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.sessions import UserSessionRepository


@dataclass(frozen=True)
class BrowserAuthenticationResult:
    authentication_session: AuthenticationSession
    user_session: UserSession


def revoke_session(session: Session, sid: str, realm_id: str) -> bool:
    """Revoke a realm session and all its families in the caller's transaction."""
    return UserSessionRepository(session).revoke(sid, realm_id, utc_now())


class UserSessionService:
    def __init__(self, session: Session, *, idle_seconds: int, max_seconds: int) -> None:
        self.repository = UserSessionRepository(session)
        self.idle_seconds = idle_seconds
        self.max_seconds = max_seconds

    def create(self, realm: Realm, client: Client, user: User) -> UserSession:
        if not (realm.enabled and client.enabled and user.enabled
                and client.realm_id == realm.id and user.realm_id == realm.id):
            raise ValueError('Invalid session identity')
        now = utc_now()
        maximum = now + timedelta(seconds=realm.sso_max_lifetime_seconds or self.max_seconds)
        idle = min(maximum, now + timedelta(seconds=realm.sso_idle_lifetime_seconds or self.idle_seconds))
        return self.repository.add(UserSession(
            realm_id=realm.id, client_id=client.id, user_id=user.id,
            created_at=now, auth_time=now, last_refresh_at=now,
            idle_expires_at=idle, max_expires_at=maximum,
        ))

    def reuse(self, sid: str, realm: Realm) -> UserSession | None:
        now = utc_now()
        session = self.repository.eligible(sid, realm.id, now)
        if session is not None:
            session.last_refresh_at = now
            session.idle_expires_at = min(
                session.max_expires_at,
                now + timedelta(seconds=realm.sso_idle_lifetime_seconds or self.idle_seconds),
            )
        return session
