"""Provision and resolve persisted realm authentication flows."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from mini_keycloak.models import AuthenticationExecution, AuthenticationFlow, Realm
from mini_keycloak.repositories.authentication import AuthenticationRepository


class AuthenticationFlowService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.repository = AuthenticationRepository(session)

    def ensure_reset_flow(self, realm: Realm) -> AuthenticationFlow:
        if realm.reset_credentials_flow_id is not None:
            flow = self.repository.get_flow(realm.id, realm.reset_credentials_flow_id)
            if flow is None:
                raise ValueError("Realm reset flow is unavailable")
            return flow
        self.session.flush()
        flow = self.session.scalar(select(AuthenticationFlow).where(
            AuthenticationFlow.realm_id == realm.id,
            AuthenticationFlow.alias == "reset credentials"))
        if flow is None:
            flow = AuthenticationFlow(realm_id=realm.id, alias="reset credentials",
                                      provider_id="basic-flow", built_in=True)
            self.session.add(flow)
            self.session.flush()
            for priority, provider in enumerate(("reset-credentials-choose-user",
                                                  "reset-credential-email", "reset-password"), start=1):
                self.session.add(AuthenticationExecution(flow_id=flow.id, authenticator=provider,
                                                        requirement="REQUIRED", priority=priority * 10))
        realm.reset_credentials_flow_id = flow.id
        self.session.flush()
        return flow

    def executions(self, flow_id: str) -> tuple[AuthenticationExecution, ...]:
        return self.repository.executions(flow_id)
