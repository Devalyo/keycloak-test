from __future__ import annotations

from dataclasses import dataclass, field
import secrets

from werkzeug.security import check_password_hash, generate_password_hash

from sqlalchemy.orm import Session

from mini_keycloak.models import AuthenticationSession as PersistentAuthenticationSession
from mini_keycloak.models import Client, Realm, ResetEmail as PersistentResetEmail
from mini_keycloak.models import User as PersistentUser
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository


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
        demo_user = User(
            id="user-demo_user",
            username="demo-user",
            email="demo-user@example.test",
            password_hash=generate_password_hash("DemoPassw0rd!"),
        )
        self.users_by_id = {demo_user.id: demo_user}
        self.user_ids_by_identifier = {demo_user.username.casefold(): demo_user.id, demo_user.email.casefold(): demo_user.id}
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


class PersistentStore:
    def __init__(self, session: Session) -> None:
        self.identities = IdentityRepository(session)
        self.authentication = AuthenticationRepository(session)

    def get_realm(self, name: str) -> Realm | None:
        return self.identities.get_realm(name)

    def get_client(self, realm_id: str, client_id: str) -> Client | None:
        return self.identities.get_client(realm_id, client_id)

    def create_auth_session(
        self,
        realm: Realm,
        client: Client,
        redirect_uri: str,
        current_execution: str,
    ) -> PersistentAuthenticationSession:
        return self.authentication.create_session(
            realm, client, redirect_uri, current_execution
        )

    def get_auth_session(self, tab_id: str) -> PersistentAuthenticationSession | None:
        return self.authentication.get_session(tab_id)

    def find_user(self, realm_id: str, identifier: str) -> PersistentUser | None:
        return self.identities.find_user(realm_id, identifier)

    def get_user(self, realm_id: str, user_id: str | None) -> PersistentUser | None:
        return self.identities.get_user(realm_id, user_id)

    def queue_reset_email(self, realm: Realm, user: PersistentUser) -> PersistentResetEmail:
        return self.authentication.queue_reset_email(realm, user)

    def password_matches(self, user: PersistentUser, raw_password: str) -> bool:
        return self.identities.password_matches(user, raw_password)

    def set_password(self, user: PersistentUser, raw_password: str) -> None:
        self.identities.set_password(user, raw_password)

    def outbox_count(self) -> int:
        return self.authentication.outbox_count()
