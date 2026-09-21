"""Required-action selection and progression for an authentication session."""

from collections.abc import Mapping

from mini_keycloak.authentication.engine import FlowOutcome
from mini_keycloak.authentication.required_actions import (
    RequiredActionContext,
    RequiredActionRegistry,
    RequiredActionResult,
    RequiredActionStatus,
)
from mini_keycloak.models import AuthenticationSession, Client, Realm
from mini_keycloak.repositories.authentication import AuthenticationRepository


class AuthenticationManager:
    def __init__(
        self,
        repository: AuthenticationRepository,
        authentication_session: AuthenticationSession,
        realm: Realm,
        client: Client,
        registry: RequiredActionRegistry,
        forms=None,
    ) -> None:
        self.repository = repository
        self.authentication_session = authentication_session
        self.realm = realm
        self.client = client
        self.registry = registry
        self.forms = forms

    def _session(self, authentication_session=None) -> AuthenticationSession:
        candidate = authentication_session or self.authentication_session
        if candidate.tab_id != self.authentication_session.tab_id:
            raise ValueError("Invalid authentication request")
        return candidate

    def next_required_action(self, authentication_session=None) -> str | None:
        pending = self._session(authentication_session).required_actions
        return pending[0] if pending else None

    def _context(self, provider_id: str) -> RequiredActionContext:
        form = self.forms.for_execution(provider_id) if self.forms is not None else None
        return RequiredActionContext(
            self.repository,
            self.authentication_session,
            self.realm,
            self.client,
            provider_id,
            form,
        )

    def _outcome(
        self, provider_id: str, result: RequiredActionResult
    ) -> FlowOutcome:
        if result.status == RequiredActionStatus.SUCCESS:
            pending = self.authentication_session.required_actions
            if not pending or pending[0] != provider_id:
                raise ValueError("Invalid authentication request")
            pending.pop(0)
            self.authentication_session.current_required_action = None
            return self.required_action_challenge()
        page = "error" if result.status == RequiredActionStatus.FAILURE else None
        return FlowOutcome(
            challenge=result.challenge,
            page=page,
            execution_id=provider_id,
            message=result.message,
        )

    def required_action_challenge(
        self, authentication_session=None
    ) -> FlowOutcome:
        auth = self._session(authentication_session)
        provider_id = self.next_required_action(auth)
        if provider_id is None:
            auth.current_required_action = None
            return FlowOutcome(complete=True)
        auth.current_required_action = provider_id
        provider = self.registry.create(provider_id, self.repository.session)
        return self._outcome(provider_id, provider.challenge(self._context(provider_id)))

    def process_required_action(
        self, provider_id: str, form: Mapping[str, str]
    ) -> FlowOutcome:
        pending = self.authentication_session.required_actions
        if (
            not pending
            or pending[0] != provider_id
            or self.authentication_session.current_required_action != provider_id
        ):
            raise ValueError("Invalid authentication request")
        provider = self.registry.create(provider_id, self.repository.session)
        return self._outcome(
            provider_id, provider.action(self._context(provider_id), form)
        )
