from sqlalchemy import select
from sqlalchemy.orm import Session

from mini_keycloak.models import Client, Credential, Realm, User
from mini_keycloak.security.passwords import PasswordService


class IdentityRepository:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.passwords = PasswordService()

    def get_realm(self, name: str) -> Realm | None:
        return self.session.scalar(select(Realm).where(Realm.name == name))

    def realms_with_normalized_name(self, normalized: str) -> list[Realm]:
        return list(self.session.scalars(
            select(Realm).where(Realm.name_normalized == normalized)
        ))

    def list_clients(self, realm_id: str) -> list[Client]:
        return list(self.session.scalars(select(Client).where(Client.realm_id == realm_id)))

    def list_users(self, realm_id: str) -> list[User]:
        # Imports must include disabled users, unlike authentication lookup.
        return list(self.session.scalars(select(User).where(User.realm_id == realm_id)))

    def get_client(self, realm_id: str, client_id: str) -> Client | None:
        return self.session.scalar(
            select(Client).where(
                Client.realm_id == realm_id,
                Client.client_id == client_id,
            )
        )

    def get_user(self, realm_id: str, user_id: str | None) -> User | None:
        if user_id is None:
            return None
        return self.session.scalar(
            select(User).where(User.realm_id == realm_id, User.id == user_id)
        )

    def find_user(self, realm_id: str, identifier: str) -> User | None:
        normalized = identifier.strip().casefold()
        user = self.session.scalar(
            select(User).where(
                User.realm_id == realm_id,
                User.enabled.is_(True),
                User.username_normalized == normalized,
            )
        )
        if user is not None:
            return user
        return self.session.scalar(
            select(User).where(
                User.realm_id == realm_id,
                User.enabled.is_(True),
                User.email_normalized == normalized,
            )
        )

    def create_realm(
        self, name: str, *, display_name: str | None = None
    ) -> Realm:
        realm = Realm(name=name, display_name=display_name)
        self.session.add(realm)
        self.session.flush()
        return realm

    def create_client(
        self,
        realm_id: str,
        client_id: str,
        *,
        redirect_uris: list[str],
        public_client: bool = True,
        standard_flow_enabled: bool = True,
        direct_access_grants_enabled: bool = False,
        pkce_policy: str = "S256",
    ) -> Client:
        if pkce_policy not in {"S256", "optional"}:
            raise ValueError("Unsupported PKCE policy")
        client = Client(
            realm_id=realm_id,
            client_id=client_id,
            public_client=public_client,
            redirect_uris=list(redirect_uris),
            standard_flow_enabled=standard_flow_enabled,
            direct_access_grants_enabled=direct_access_grants_enabled,
            pkce_policy=pkce_policy,
        )
        self.session.add(client)
        self.session.flush()
        return client

    def create_user(
        self,
        realm_id: str,
        username: str,
        email: str | None,
        password: str,
    ) -> User:
        user = User(
            realm_id=realm_id,
            username=username,
            username_normalized=username.strip().casefold(),
            email=email,
            email_normalized=email.strip().casefold() if email else None,
        )
        self.session.add(user)
        self.session.flush()
        self.set_password(user, password)
        return user

    def set_password(self, user: User, raw_password: str) -> None:
        credential = self.session.scalar(
            select(Credential).where(
                Credential.user_id == user.id,
                Credential.type == "password",
            )
        )
        if credential is None:
            credential = Credential(user_id=user.id, type="password", secret_hash="")
            self.session.add(credential)
        credential.secret_hash = self.passwords.hash(raw_password)

    def password_matches(self, user: User, raw_password: str) -> bool:
        credential = self.session.scalar(
            select(Credential).where(
                Credential.user_id == user.id,
                Credential.type == "password",
            )
        )
        return credential is not None and self.passwords.verify(
            credential.secret_hash, raw_password
        )
