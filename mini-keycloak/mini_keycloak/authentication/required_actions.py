from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from mini_keycloak.authentication.providers import ProviderRegistry
from mini_keycloak.models import AuthenticationSession, Client, Realm, User
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository


class RequiredActionStatus(str, Enum):
    CHALLENGE = "CHALLENGE"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


@dataclass(frozen=True)
class RequiredActionResult:
    status: RequiredActionStatus
    challenge: str | None = None
    message: str = ""


@dataclass(frozen=True)
class RequiredActionContext:
    repository: AuthenticationRepository
    authentication_session: AuthenticationSession
    realm: Realm
    client: Client
    provider_id: str
    form: object | None = None

    @property
    def user(self) -> User | None:
        return IdentityRepository(self.repository.session).get_user(
            self.realm.id, self.authentication_session.selected_user_id)


class RequiredActionProvider(Protocol):
    def challenge(self, context: RequiredActionContext) -> RequiredActionResult: ...

    def action(
        self, context: RequiredActionContext, form: Mapping[str, str]
    ) -> RequiredActionResult: ...


class RequiredActionRegistry(ProviderRegistry[RequiredActionProvider]):
    pass
