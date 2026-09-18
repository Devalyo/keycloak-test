"""Validate a browser authentication transaction before dispatching its flow."""

from collections.abc import Mapping

from sqlalchemy.orm import Session

from mini_keycloak.authentication.constants import CURRENT_AUTHENTICATION_EXECUTION
from mini_keycloak.authentication.engine import AuthenticatorRegistry, DefaultAuthenticationFlow, FlowOutcome
from mini_keycloak.models import AuthenticationSession, Client, Realm, User
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository


class AuthenticationProcessor:
    def __init__(self, session: Session, *, realm_name: str, client_id: str,
                 tab_id: str, registry: AuthenticatorRegistry) -> None:
        self.repository = AuthenticationRepository(session)
        self.identities = IdentityRepository(session)
        self.realm_name = realm_name
        self.client_id = client_id
        self.tab_id = tab_id
        self.registry = registry

    @property
    def authentication_session(self) -> AuthenticationSession:
        auth = self.repository.get_session(self.tab_id)
        if auth is None:
            raise ValueError("Invalid authentication request")
        return auth

    @property
    def user(self) -> User | None:
        return self._validate_user(self.authentication_session)

    def _validate_user(self, auth: AuthenticationSession) -> User | None:
        user = self.identities.get_user(auth.realm_id, auth.selected_user_id)
        if auth.selected_user_id is not None and (user is None or not user.enabled):
            raise ValueError("Invalid authentication request")
        return user

    def _flow(self, requested_executions: tuple[str, ...] = ()) -> DefaultAuthenticationFlow:
        auth = self.authentication_session
        realm = self.repository.session.get(Realm, auth.realm_id)
        client = self.repository.session.get(Client, auth.client_id)
        if (realm is None or not realm.enabled or realm.name != self.realm_name
                or client is None or not client.enabled or client.realm_id != realm.id
                or client.client_id != self.client_id or auth.flow_id is None
                or realm.reset_credentials_flow_id != auth.flow_id):
            raise ValueError("Invalid authentication request")
        flow = self.repository.get_flow(realm.id, auth.flow_id)
        if flow is None or flow.provider_id != "basic-flow":
            raise ValueError("Invalid authentication request")
        self._validate_user(auth)
        executions = self.repository.executions(flow.id)
        if not executions or any(execution.requirement != "REQUIRED" for execution in executions):
            raise ValueError("Invalid authentication request")
        current = auth.auth_notes.get(CURRENT_AUTHENTICATION_EXECUTION)
        execution_ids = {execution.id for execution in executions}
        if ((current is not None and current not in execution_ids)
                or any(execution_id not in execution_ids for execution_id in requested_executions)):
            raise ValueError("Invalid authentication request")
        return DefaultAuthenticationFlow(self.repository, auth, realm, client, executions, self.registry)

    def process_flow(self) -> FlowOutcome:
        return self._flow().process_flow()

    def process_action(self, execution_id: str, form: Mapping[str, str]) -> FlowOutcome:
        requested = (execution_id,)
        if "authenticationExecution" in form:
            requested += (form["authenticationExecution"],)
        return self._flow(requested).process_action(execution_id, form)
