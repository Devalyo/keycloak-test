from collections.abc import Mapping
from datetime import datetime, timedelta
import hashlib
import secrets

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from mini_keycloak.models import AuthenticationExecution, AuthenticationFlow, AuthenticationSession, Client, Realm, ResetEmail, User
from mini_keycloak.models.identity import utc_now


class AuthenticationRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_flow(self, realm_id: str, flow_id: str) -> AuthenticationFlow | None:
        return self.session.scalar(select(AuthenticationFlow).where(
            AuthenticationFlow.realm_id == realm_id, AuthenticationFlow.id == flow_id))

    def get_execution(self, realm_id: str, execution_id: str) -> AuthenticationExecution | None:
        return self.session.scalar(select(AuthenticationExecution).join(AuthenticationFlow).where(
            AuthenticationFlow.realm_id == realm_id, AuthenticationExecution.id == execution_id))

    def executions(self, flow_id: str) -> tuple[AuthenticationExecution, ...]:
        return tuple(self.session.scalars(select(AuthenticationExecution).where(
            AuthenticationExecution.flow_id == flow_id).order_by(
                AuthenticationExecution.priority, AuthenticationExecution.id)))

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

    def update_session(
        self,
        auth_session: AuthenticationSession,
        *,
        current_execution: str | None = None,
        execution_status: Mapping[str, str] | None = None,
        auth_notes: Mapping[str, str | None] | None = None,
    ) -> None:
        """Stage a versioned transition in the caller's transaction."""
        if current_execution is not None:
            auth_session.current_execution = current_execution
        for execution_id, status in (execution_status or {}).items():
            auth_session.execution_status[execution_id] = status
        for name, value in (auth_notes or {}).items():
            if value is None:
                auth_session.auth_notes.pop(name, None)
            else:
                auth_session.auth_notes[name] = value

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

    def get_reset_email(self, token_id: str) -> ResetEmail | None:
        return self.session.scalar(select(ResetEmail).where(ResetEmail.token_id == token_id))

    def consume_reset_email(self, message: ResetEmail, now: datetime) -> ResetEmail | None:
        return self.session.scalar(update(ResetEmail).where(
            ResetEmail.id == message.id,
            ResetEmail.realm_id == message.realm_id,
            ResetEmail.client_id == message.client_id,
            ResetEmail.user_id == message.user_id,
            ResetEmail.authentication_session_id == message.authentication_session_id,
            ResetEmail.token_id == message.token_id,
            ResetEmail.action_token_hash == message.action_token_hash,
            ResetEmail.consumed_at.is_(None),
            ResetEmail.consumed.is_(False),
            ResetEmail.expires_at > now,
        ).values(consumed_at=now, consumed=True).returning(ResetEmail)
            .execution_options(populate_existing=True, synchronize_session=False))
