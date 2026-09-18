from dataclasses import dataclass
from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import StaleDataError

from mini_keycloak.authentication import (
    AuthenticationProcessor,
    AuthenticatorRegistry,
    AuthenticatorResult,
    FlowStatus,
)
from mini_keycloak.authentication.constants import (
    AUTHENTICATION_FLOW_COMPLETED,
    AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED,
    CURRENT_AUTHENTICATION_EXECUTION,
)
from mini_keycloak.extensions import db
from mini_keycloak.models import (
    AuthenticationExecution,
    AuthenticationFlow,
    AuthenticationSession,
    AuthorizationCode,
    User,
    UserSession,
)
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.authentication_flows import AuthenticationFlowService


class RecordingAuthenticator:
    def __init__(self, page, calls):
        self.calls = calls
        self.authentication_result = AuthenticatorResult(FlowStatus.CHALLENGE, page=page)
        self.action_result = AuthenticatorResult(FlowStatus.SUCCESS)

    def authenticate(self, context):
        self.calls.append((context.execution.id, "authenticate", context.user))
        return self.authentication_result

    def action(self, context, form):
        self.calls.append((context.execution.id, "action", dict(form)))
        return self.action_result


@dataclass
class FlowHarness:
    session: AuthenticationSession
    executions: tuple
    providers: tuple
    registry: AuthenticatorRegistry
    calls: list

    def processor(self, database=None, **overrides):
        arguments = dict(realm_name="flow-realm", client_id="flow-client",
                         tab_id=self.session.tab_id, registry=self.registry)
        arguments.update(overrides)
        return AuthenticationProcessor(database or db.session, **arguments)


@pytest.fixture
def flow(db_app):
    with db_app.app_context():
        identities = IdentityRepository(db.session)
        realm = identities.create_realm("flow-realm")
        client = identities.create_client(realm.id, "flow-client",
                                          redirect_uris=["https://client.example/callback"])
        configured_flow = AuthenticationFlowService(db.session).ensure_reset_flow(realm)
        repository = AuthenticationRepository(db.session)
        executions = repository.executions(configured_flow.id)
        auth = repository.create_session(realm, client, client.redirect_uris[0], executions[0].id)
        auth.flow_id = configured_flow.id
        calls = []
        providers = tuple(RecordingAuthenticator(page, calls)
                          for page in ("account", "message", "credential"))
        registry = AuthenticatorRegistry(dict(zip(
            (execution.authenticator for execution in executions), providers)))
        db.session.commit()
        yield FlowHarness(auth, executions, providers, registry, calls)


def test_challenge_persists_current_opaque_execution(flow):
    outcome = flow.processor().process_flow()
    assert (outcome.page, outcome.execution_id, outcome.complete) == (
        "account", flow.executions[0].id, False)
    db.session.commit()
    db.session.expire_all()
    assert flow.session.auth_notes[CURRENT_AUTHENTICATION_EXECUTION] == flow.executions[0].id
    assert flow.session.current_execution == flow.executions[0].id
    assert flow.session.execution_status == {flow.executions[0].id: "CHALLENGE"}


def test_successful_action_persists_success_and_advances(flow):
    flow.processor().process_flow()
    outcome = flow.processor().process_action(flow.executions[0].id, {"value": "provided"})
    db.session.commit()
    db.session.expire_all()
    assert outcome.page == "message"
    assert outcome.execution_id == flow.executions[1].id
    assert flow.session.execution_status == {
        flow.executions[0].id: "SUCCESS", flow.executions[1].id: "CHALLENGE"}
    assert flow.calls == [(flow.executions[0].id, "authenticate", None),
                          (flow.executions[0].id, "action", {"value": "provided"}),
                          (flow.executions[1].id, "authenticate", None)]


def test_traversal_uses_persisted_priority(flow):
    flow.executions[2].priority = 5
    db.session.commit()
    outcome = flow.processor().process_flow()
    assert outcome.execution_id == flow.executions[2].id
    assert len(flow.calls) == 1


def test_completed_executions_are_skipped_on_resume_and_repeated_action(flow):
    flow.session.execution_status[flow.executions[0].id] = "SUCCESS"
    flow.processor().process_flow()
    flow.processor().process_action(flow.executions[0].id, {})
    assert flow.calls == [(flow.executions[1].id, "authenticate", None)] * 2
    assert flow.session.execution_status[flow.executions[0].id] == "SUCCESS"


def test_fork_records_current_execution_and_can_resume(flow):
    flow.providers[0].authentication_result = AuthenticatorResult(FlowStatus.SUCCESS)
    flow.providers[1].authentication_result = AuthenticatorResult(
        FlowStatus.FORK, page="login", message="Continue with your instructions.")
    outcome = flow.processor().process_flow()
    assert (outcome.page, outcome.message, outcome.complete) == (
        "login", "Continue with your instructions.", False)
    db.session.commit()
    db.session.expire_all()
    assert flow.session.execution_status[flow.executions[1].id] == "FORK"
    assert flow.session.auth_notes[CURRENT_AUTHENTICATION_EXECUTION] == flow.executions[1].id
    flow.providers[1].authentication_result = AuthenticatorResult(FlowStatus.SUCCESS)
    resumed = flow.processor().process_flow()
    assert resumed.execution_id == flow.executions[2].id
    assert flow.session.execution_status[flow.executions[1].id] == "SUCCESS"


@pytest.mark.parametrize("phase", ["authenticate", "action"])
def test_failure_stops_traversal_without_completion(flow, phase):
    result = AuthenticatorResult(FlowStatus.FAILURE, error="invalid_request")
    if phase == "authenticate":
        flow.providers[0].authentication_result = result
        outcome = flow.processor().process_flow()
    else:
        flow.providers[0].action_result = result
        outcome = flow.processor().process_action(flow.executions[0].id, {})
    assert outcome.page == "error"
    assert not outcome.complete
    assert len(flow.calls) == 1
    assert flow.session.execution_status[flow.executions[0].id] == "FAILURE"
    assert AUTHENTICATION_FLOW_COMPLETED not in flow.session.auth_notes


def test_action_challenge_keeps_execution_pending(flow):
    flow.providers[0].action_result = AuthenticatorResult(
        FlowStatus.CHALLENGE, page="account", message="Enter a value.")
    outcome = flow.processor().process_action(flow.executions[0].id, {})
    assert outcome.message == "Enter a value."
    assert outcome.execution_id == flow.executions[0].id
    assert not outcome.complete
    assert flow.session.execution_status == {flow.executions[0].id: "CHALLENGE"}


def test_completion_requires_every_required_execution_and_issues_no_artifacts(flow):
    flow.providers[0].authentication_result = AuthenticatorResult(FlowStatus.SUCCESS)
    flow.providers[1].authentication_result = AuthenticatorResult(FlowStatus.SUCCESS)
    pending = flow.processor().process_flow()
    assert not pending.complete
    assert AUTHENTICATION_FLOW_COMPLETED not in flow.session.auth_notes
    complete = flow.processor().process_action(flow.executions[2].id, {})
    assert (complete.page, complete.execution_id, complete.complete) == (None, None, True)
    assert set(flow.session.execution_status.values()) == {"SUCCESS"}
    assert flow.session.auth_notes[AUTHENTICATION_FLOW_COMPLETED] == "true"
    assert CURRENT_AUTHENTICATION_EXECUTION not in flow.session.auth_notes
    assert db.session.scalar(select(func.count(UserSession.id))) == 0
    assert db.session.scalar(select(func.count(AuthorizationCode.id))) == 0


def test_selector_reentry_uses_session_current_execution(flow):
    first, second, _ = flow.executions
    selected = flow.processor().process_action(first.id, {"tryAnotherWay": ""})
    assert (selected.page, selected.execution_id) == ("selector", first.id)
    assert not flow.calls
    assert flow.session.auth_notes[AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED] == "true"
    flow.providers[1].authentication_result = AuthenticatorResult(FlowStatus.FORK, page="login")
    flow.processor().process_action(first.id, {"value": "provided"})
    assert flow.session.auth_notes[CURRENT_AUTHENTICATION_EXECUTION] == second.id
    flow.calls.clear()
    db.session.commit()
    outcome = flow.processor().process_flow()
    assert (outcome.page, outcome.execution_id) == ("selector", second.id)
    assert not flow.calls


def test_explicit_selection_clears_selector_and_authenticates_selected_execution(flow):
    first = flow.executions[0]
    flow.processor().process_action(first.id, {"tryAnotherWay": ""})
    outcome = flow.processor().process_action(first.id, {"authenticationExecution": first.id})
    assert outcome.page == "account"
    assert AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED not in flow.session.auth_notes
    assert flow.calls == [(first.id, "authenticate", None)]


def foreign_execution(flow, *, same_realm):
    realm_id = flow.session.realm_id
    if not same_realm:
        realm_id = IdentityRepository(db.session).create_realm("second-realm").id
    other_flow = AuthenticationFlow(realm_id=realm_id, alias="second flow", provider_id="basic-flow")
    db.session.add(other_flow)
    db.session.flush()
    execution = AuthenticationExecution(flow_id=other_flow.id, authenticator="other-provider",
                                        requirement="REQUIRED", priority=10)
    db.session.add(execution)
    db.session.commit()
    return execution


@pytest.mark.parametrize("kind", ["unknown", "other-flow", "other-realm"])
@pytest.mark.parametrize("dispatch", ["action", "selection", "current"])
def test_execution_must_belong_to_configured_flow_before_dispatch(flow, kind, dispatch):
    execution_id = "unknown-execution"
    if kind != "unknown":
        execution_id = foreign_execution(flow, same_realm=kind == "other-flow").id
    processor = flow.processor()
    with pytest.raises(ValueError, match="Invalid authentication request"):
        if dispatch == "action":
            processor.process_action(execution_id, {})
        elif dispatch == "selection":
            processor.process_action(flow.executions[0].id, {"authenticationExecution": execution_id})
        else:
            flow.session.auth_notes[CURRENT_AUTHENTICATION_EXECUTION] = execution_id
            processor.process_flow()
    assert not flow.calls
    assert not flow.session.execution_status


@pytest.mark.parametrize("field,value", [
    ("realm_name", "missing-realm"), ("client_id", "missing-client"), ("tab_id", "missing-tab")])
def test_request_identifiers_must_match_session(flow, field, value):
    with pytest.raises(ValueError, match="Invalid authentication request"):
        flow.processor(**{field: value}).process_flow()
    assert not flow.calls


@pytest.mark.parametrize("condition", [
    "disabled-realm", "disabled-client", "foreign-client", "expired-session", "missing-flow",
    "foreign-flow", "unbound-flow", "foreign-user", "disabled-user"])
def test_processor_validates_session_ownership_and_availability(flow, condition):
    identities = IdentityRepository(db.session)
    if condition == "disabled-realm":
        flow.session.realm.enabled = False
    elif condition == "disabled-client":
        flow.session.client.enabled = False
    elif condition == "foreign-client":
        other = identities.create_realm("second-realm")
        client = identities.create_client(other.id, "flow-client", redirect_uris=[])
        flow.session.client_id = client.id
    elif condition == "expired-session":
        flow.session.expires_at = utc_now() - timedelta(seconds=1)
    elif condition == "missing-flow":
        flow.session.flow_id = None
    elif condition == "foreign-flow":
        flow.session.flow_id = foreign_execution(flow, same_realm=False).flow_id
    elif condition == "unbound-flow":
        flow.session.flow_id = foreign_execution(flow, same_realm=True).flow_id
    else:
        realm_id = flow.session.realm_id
        if condition == "foreign-user":
            realm_id = identities.create_realm("second-realm").id
        user = User(realm_id=realm_id, username="selected", username_normalized="selected",
                    enabled=condition != "disabled-user")
        db.session.add(user)
        db.session.flush()
        flow.session.selected_user_id = user.id
    db.session.commit()
    with pytest.raises(ValueError, match="Invalid authentication request"):
        flow.processor().process_flow()
    assert not flow.calls
    assert not flow.session.execution_status


def test_processor_exposes_selected_user_to_authenticator(flow):
    user = User(realm_id=flow.session.realm_id, username="selected", username_normalized="selected")
    db.session.add(user)
    db.session.flush()
    flow.session.selected_user_id = user.id
    db.session.commit()
    processor = flow.processor()
    processor.process_flow()
    assert processor.authentication_session is flow.session
    assert processor.user is user
    assert flow.calls[0][2] is user


def test_unknown_provider_fails_without_completing(flow):
    flow.executions[0].authenticator = "unregistered-provider"
    db.session.commit()
    with pytest.raises(ValueError, match="Invalid authentication request"):
        flow.processor().process_flow()
    assert not flow.session.execution_status


def test_processor_changes_remain_in_callers_transaction(flow):
    flow.processor().process_flow()
    db.session.flush()
    db.session.rollback()
    assert flow.session.execution_status == {}
    assert flow.session.auth_notes == {}


def test_concurrent_processor_transition_rejects_stale_writer(flow):
    flow.processor().process_flow()
    db.session.commit()
    tab_id = flow.session.tab_id
    sessions = sessionmaker(bind=db.engine, expire_on_commit=False)
    with sessions() as winner, sessions() as loser:
        winner_auth = winner.get(AuthenticationSession, tab_id)
        loser_auth = loser.get(AuthenticationSession, tab_id)
        assert winner_auth.version == loser_auth.version
        flow.processor(winner).process_flow()
        winner.commit()
        with pytest.raises(StaleDataError):
            flow.processor(loser).process_flow()
            loser.commit()
        loser.rollback()
    db.session.expire_all()
    assert flow.session.execution_status == {flow.executions[0].id: "CHALLENGE"}
    assert flow.session.version == winner_auth.version
