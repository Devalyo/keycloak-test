"""Authenticator dispatch and ordered authentication-flow traversal."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from mini_keycloak.authentication.constants import (
    AUTHENTICATION_FLOW_COMPLETED,
    AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED,
    CURRENT_AUTHENTICATION_EXECUTION,
)
from mini_keycloak.authentication.providers import ProviderRegistry
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
    challenge: str | None = None
    message: str = ""
    error: str | None = None


@dataclass(frozen=True)
class FlowOutcome:
    challenge: str | None = None
    page: str | None = None
    execution_id: str | None = None
    message: str = ""
    complete: bool = False
    forked: bool = False


@dataclass
class AuthenticationFlowContext:
    repository: AuthenticationRepository
    authentication_session: AuthenticationSession
    realm: Realm
    client: Client
    execution: AuthenticationExecution
    authenticator: object
    form: object | None = None
    _result: AuthenticatorResult | None = field(default=None, init=False, repr=False)

    @property
    def user(self) -> User | None:
        return IdentityRepository(self.repository.session).get_user(
            self.realm.id, self.authentication_session.selected_user_id
        )

    @property
    def result(self) -> AuthenticatorResult:
        if self._result is None:
            raise ValueError("Invalid authentication request")
        return self._result

    def _set_result(self, result: AuthenticatorResult) -> None:
        if self._result is not None:
            raise ValueError("Invalid authentication request")
        self._result = result

    def success(self) -> None:
        self._set_result(AuthenticatorResult(FlowStatus.SUCCESS))

    def challenge(self, response: str, message: str = "") -> None:
        self._set_result(
            AuthenticatorResult(FlowStatus.CHALLENGE, challenge=response, message=message)
        )

    def fork(self, message: str = "") -> None:
        self._set_result(AuthenticatorResult(FlowStatus.FORK, message=message))

    def failure(
        self,
        error: str = "invalid_request",
        message: str = "Invalid authentication request",
    ) -> None:
        self._set_result(
            AuthenticatorResult(FlowStatus.FAILURE, message=message, error=error)
        )


# Compatibility name for callers that construct an authentication context directly.
AuthenticatorContext = AuthenticationFlowContext


class Authenticator(Protocol):
    def authenticate(self, context: AuthenticationFlowContext) -> None: ...

    def action(
        self, context: AuthenticationFlowContext, form: Mapping[str, str]
    ) -> None: ...


class AuthenticatorRegistry(ProviderRegistry[Authenticator]):
    pass


ContextFactory = Callable[
    [AuthenticationExecution, Authenticator, tuple[AuthenticationExecution, ...]],
    AuthenticationFlowContext,
]


class DefaultAuthenticationFlow:
    def __init__(
        self,
        repository: AuthenticationRepository,
        authentication_session: AuthenticationSession,
        executions: tuple[AuthenticationExecution, ...],
        registry: AuthenticatorRegistry,
        context_factory: ContextFactory,
    ) -> None:
        self.repository = repository
        self.authentication_session = authentication_session
        self.executions = executions
        self.registry = registry
        self.context_factory = context_factory

    def _execution(self, execution_id: str) -> AuthenticationExecution:
        for execution in self.executions:
            if execution.id == execution_id:
                return execution
        raise ValueError("Invalid authentication request")

    def _context(
        self, execution: AuthenticationExecution, authenticator: Authenticator
    ) -> AuthenticationFlowContext:
        return self.context_factory(execution, authenticator, self.executions)

    def _successful(self, execution: AuthenticationExecution) -> bool:
        return (
            self.authentication_session.execution_status.get(execution.id)
            == FlowStatus.SUCCESS.value
        )

    def process_result(
        self, context: AuthenticationFlowContext, *, is_action: bool
    ) -> FlowOutcome | None:
        result = context.result
        execution = context.execution
        self.repository.update_session(
            self.authentication_session,
            current_execution=execution.id,
            execution_status={execution.id: result.status.value},
            auth_notes={
                CURRENT_AUTHENTICATION_EXECUTION: execution.id,
                AUTHENTICATION_FLOW_COMPLETED: None,
            },
        )
        if result.status == FlowStatus.SUCCESS:
            return None
        if result.status == FlowStatus.FAILURE:
            return FlowOutcome(
                page="error", execution_id=execution.id, message=result.message
            )
        if result.status == FlowStatus.FORK:
            return FlowOutcome(
                execution_id=execution.id,
                message=result.message,
                forked=True,
            )
        if result.status == FlowStatus.CHALLENGE:
            return FlowOutcome(
                challenge=result.challenge,
                execution_id=execution.id,
                message=result.message,
            )
        raise ValueError("Invalid authentication request")

    def _authenticate(self, execution: AuthenticationExecution) -> FlowOutcome | None:
        authenticator = self.registry.create(
            execution.authenticator, self.repository.session
        )
        context = self._context(execution, authenticator)
        authenticator.authenticate(context)
        return self.process_result(context, is_action=False)

    def _selector_challenge(self, execution: AuthenticationExecution) -> FlowOutcome:
        authenticator = self.registry.create(
            execution.authenticator, self.repository.session
        )
        context = self._context(execution, authenticator)
        if context.form is None:
            raise ValueError("Invalid authentication request")
        return FlowOutcome(
            challenge=context.form.create_select_authenticator(account=True),
            execution_id=execution.id,
        )

    def on_flow_executions_successful(self) -> FlowOutcome:
        self.repository.update_session(
            self.authentication_session,
            auth_notes={
                AUTHENTICATION_FLOW_COMPLETED: "true",
                CURRENT_AUTHENTICATION_EXECUTION: None,
                AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED: None,
            },
        )
        return FlowOutcome(complete=True)

    def _traverse(self) -> FlowOutcome:
        for execution in self.executions:
            if self._successful(execution):
                continue
            outcome = self._authenticate(execution)
            if outcome is not None:
                return outcome
        return self.on_flow_executions_successful()

    def process_flow(self) -> FlowOutcome:
        notes = self.authentication_session.auth_notes
        selector_displayed = notes.get(AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED)
        if selector_displayed is not None and selector_displayed.lower() == "true":
            current = notes.get(CURRENT_AUTHENTICATION_EXECUTION)
            if current is not None:
                execution = self._execution(current)
                return self._selector_challenge(execution)
        return self._traverse()

    def process_action(
        self, execution_id: str, form: Mapping[str, str]
    ) -> FlowOutcome:
        execution = self._execution(execution_id)
        notes = self.authentication_session.auth_notes
        if notes.get(CURRENT_AUTHENTICATION_EXECUTION) != execution.id:
            raise ValueError("Invalid authentication request")
        if "authenticationExecution" in form:
            if notes.get(AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED) != "true":
                raise ValueError("Invalid authentication request")
            selected = self._execution(form["authenticationExecution"])
            self.repository.update_session(
                self.authentication_session,
                auth_notes={AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED: None},
            )
            outcome = None if self._successful(selected) else self._authenticate(selected)
            return outcome if outcome is not None else self._traverse()
        if "tryAnotherWay" in form:
            self.repository.update_session(
                self.authentication_session,
                current_execution=execution.id,
                auth_notes={
                    AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED: "true",
                    CURRENT_AUTHENTICATION_EXECUTION: execution.id,
                },
            )
            return self._selector_challenge(execution)
        if self._successful(execution):
            raise ValueError("Invalid authentication request")
        authenticator = self.registry.create(
            execution.authenticator, self.repository.session
        )
        context = self._context(execution, authenticator)
        authenticator.action(context, form)
        outcome = self.process_result(context, is_action=True)
        return outcome if outcome is not None else self._traverse()
