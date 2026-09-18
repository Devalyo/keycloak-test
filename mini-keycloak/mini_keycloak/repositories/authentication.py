from datetime import timedelta
import hashlib
import secrets

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mini_keycloak.models import AuthenticationSession, Client, Realm, ResetEmail, User
from mini_keycloak.models.identity import utc_now


class AuthenticationRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_session(
        self,
        realm: Realm,
        client: Client,
        redirect_uri: str,
        current_execution: str,
    ) -> AuthenticationSession:
        auth_session = AuthenticationSession(
            tab_id=secrets.token_urlsafe(18),
            realm_id=realm.id,
            client_id=client.id,
            redirect_uri=redirect_uri,
            current_execution=current_execution,
            expires_at=utc_now() + timedelta(minutes=30),
        )
        self.session.add(auth_session)
        self.session.flush()
        return auth_session

    def get_session(self, tab_id: str) -> AuthenticationSession | None:
        return self.session.scalar(
            select(AuthenticationSession).where(
                AuthenticationSession.tab_id == tab_id,
                AuthenticationSession.expires_at > utc_now(),
            )
        )

    def queue_reset_email(self, realm: Realm, user: User) -> ResetEmail:
        raw_token = secrets.token_urlsafe(32)
        message = ResetEmail(
            realm_id=realm.id,
            user_id=user.id,
            recipient=user.email or "",
            action_token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
            expires_at=utc_now() + timedelta(hours=12),
        )
        self.session.add(message)
        self.session.flush()
        return message

    def outbox_count(self) -> int:
        return self.session.scalar(select(func.count(ResetEmail.id))) or 0
