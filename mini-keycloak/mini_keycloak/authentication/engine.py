"""Typed authenticator dispatch and ordered authentication-flow traversal."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from mini_keycloak.authentication.constants import (
    AUTHENTICATION_FLOW_COMPLETED,
    AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED,
    CURRENT_AUTHENTICATION_EXECUTION,
)
from mini_keycloak.models import AuthenticationExecution, AuthenticationSession, Client, Realm, User
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository


class FlowStatus(str, Enum):
    SUCCESS = "SUCCESS"
    CHALLENGE = "CHALLENGE"
    FORK = "FORK"
    FAILURE = "FAILURE"


@dataclass(frozen=True)
class AuthenticatorResult:
    status: FlowStatus
    page: str | None = None
    message: str = ""
    error: str | None = None


@dataclass(frozen=True)
class FlowOutcome:
    page: str | None = None
    execution_id: str | None = None
    message: str = ""
    complete: bool = False


@dataclass(frozen=True)
class AuthenticatorContext:
    repository: AuthenticationRepository
    authentication_session: AuthenticationSession
    realm: Realm
    client: Client
    execution: AuthenticationExecution

    @property
    def user(self) -> User | None:
        return IdentityRepository(self.repository.session).get_user(
            self.realm.id, self.authentication_session.selected_user_id)


class Authenticator(Protocol):
    def authenticate(self, context: AuthenticatorContext) -> AuthenticatorResult: ...

    def action(self, context: AuthenticatorContext, form: Mapping[str, str]) -> AuthenticatorResult: ...


class AuthenticatorRegistry:
    def __init__(self, providers: Mapping[str, Authenticator]) -> None:
        self.providers = dict(providers)

    def get(self, provider_id: str) -> Authenticator:
        provider = self.providers.get(provider_id)
        if provider is None:
            raise ValueError("Invalid authentication request")
        return provider


class DefaultAuthenticationFlow:
    def __init__(self, repository: AuthenticationRepository,
                 authentication_session: AuthenticationSession,
                 realm: Realm, client: Client,
                 executions: tuple[AuthenticationExecution, ...],
                 registry: AuthenticatorRegistry) -> None:
        self.repository = repository
        self.authentication_session = authentication_session
        self.realm = realm
        self.client = client
        self.executions = executions
        self.registry = registry

    def _execution(self, execution_id: str) -> AuthenticationExecution:
        for execution in self.executions:
            if execution.id == execution_id:
                return execution
        raise ValueError("Invalid authentication request")

    def _context(self, execution: AuthenticationExecution) -> AuthenticatorContext:
        return AuthenticatorContext(self.repository, self.authentication_session,
                                    self.realm, self.client, execution)

    def _successful(self, execution: AuthenticationExecution) -> bool:
        return self.authentication_session.execution_status.get(execution.id) == FlowStatus.SUCCESS.value

    def _record(self, execution: AuthenticationExecution,
                result: AuthenticatorResult) -> FlowOutcome | None:
        self.repository.update_session(
            self.authentication_session, current_execution=execution.id,
            execution_status={execution.id: result.status.value},
            auth_notes={CURRENT_AUTHENTICATION_EXECUTION: execution.id,
                        AUTHENTICATION_FLOW_COMPLETED: None})
        if result.status == FlowStatus.SUCCESS:
            return None
        page = result.page
        if result.status == FlowStatus.FAILURE:
            page = page or "error"
        return FlowOutcome(page=page, execution_id=execution.id, message=result.message)

    def _authenticate(self, execution: AuthenticationExecution) -> FlowOutcome | None:
        result = self.registry.get(execution.authenticator).authenticate(self._context(execution))
        return self._record(execution, result)

    def _traverse(self) -> FlowOutcome:
        for execution in self.executions:
            if self._successful(execution):
                continue
            outcome = self._authenticate(execution)
            if outcome is not None:
                return outcome
        self.repository.update_session(
            self.authentication_session,
            auth_notes={AUTHENTICATION_FLOW_COMPLETED: "true",
                        CURRENT_AUTHENTICATION_EXECUTION: None,
                        AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED: None})
        return FlowOutcome(complete=True)

    def process_flow(self) -> FlowOutcome:
        notes = self.authentication_session.auth_notes
        if notes.get(AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED, "").casefold() == "true":
            execution_id = notes.get(CURRENT_AUTHENTICATION_EXECUTION)
            if execution_id is not None:
                execution = self._execution(execution_id)
                return FlowOutcome(page="selector", execution_id=execution.id)
        return self._traverse()

    def process_action(self, execution_id: str, form: Mapping[str, str]) -> FlowOutcome:
        execution = self._execution(execution_id)
        if "authenticationExecution" in form:
            execution = self._execution(form["authenticationExecution"])
            self.repository.update_session(
                self.authentication_session,
                auth_notes={AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED: None})
            outcome = None if self._successful(execution) else self._authenticate(execution)
            return outcome if outcome is not None else self._traverse()
        if "tryAnotherWay" in form:
            current = self.authentication_session.auth_notes.get(
                CURRENT_AUTHENTICATION_EXECUTION, execution.id)
            self._execution(current)
            self.repository.update_session(
                self.authentication_session, current_execution=current,
                auth_notes={AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED: "true",
                            CURRENT_AUTHENTICATION_EXECUTION: current})
            return FlowOutcome(page="selector", execution_id=current)
        if self._successful(execution):
            return self._traverse()
        result = self.registry.get(execution.authenticator).action(self._context(execution), form)
        outcome = self._record(execution, result)
        return outcome if outcome is not None else self._traverse()
