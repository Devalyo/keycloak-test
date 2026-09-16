from __future__ import annotations

from dataclasses import dataclass, field
import secrets

from werkzeug.security import check_password_hash, generate_password_hash


@dataclass
class User:
    id: str
    username: str
    email: str
    password_hash: str
    email_verified: bool = False


@dataclass
class AuthenticationSession:
    tab_id: str
    client_id: str
    redirect_uri: str
    current_execution: str
    selected_user_id: str | None = None
    auth_notes: dict[str, str] = field(default_factory=dict)
    password_update_allowed: bool = False


@dataclass
class ResetEmail:
    recipient: str
    user_id: str
    action_token: str
    consumed: bool = False


class InMemoryStore:
    def __init__(self) -> None:
        victim = User(
            id="user-victim",
            username="victim",
            email="victim@poc.local",
            password_hash=generate_password_hash("OriginalPassw0rd!"),
        )
        self.users_by_id = {victim.id: victim}
        self.user_ids_by_identifier = {victim.username.casefold(): victim.id, victim.email.casefold(): victim.id}
        self.sessions: dict[str, AuthenticationSession] = {}
        self.outbox: list[ResetEmail] = []

    def create_auth_session(self, client_id: str, redirect_uri: str, current_execution: str) -> AuthenticationSession:
        session = AuthenticationSession(
            tab_id=secrets.token_urlsafe(12),
            client_id=client_id,
            redirect_uri=redirect_uri,
            current_execution=current_execution,
        )
        self.sessions[session.tab_id] = session
        return session

    def get_auth_session(self, tab_id: str) -> AuthenticationSession | None:
        return self.sessions.get(tab_id)

    def find_user(self, identifier: str) -> User | None:
        user_id = self.user_ids_by_identifier.get(identifier.casefold())
        return self.users_by_id.get(user_id) if user_id else None

    def get_user(self, user_id: str | None) -> User | None:
        return self.users_by_id.get(user_id) if user_id else None

    def queue_reset_email(self, user: User) -> ResetEmail:
        message = ResetEmail(
            recipient=user.email,
            user_id=user.id,
            action_token=secrets.token_urlsafe(24),
        )
        self.outbox.append(message)
        return message

    @staticmethod
    def password_matches(user: User, raw_password: str) -> bool:
        return check_password_hash(user.password_hash, raw_password)

    @staticmethod
    def set_password(user: User, raw_password: str) -> None:
        user.password_hash = generate_password_hash(raw_password)
