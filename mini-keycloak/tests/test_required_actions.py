from sqlalchemy import func, select

from mini_keycloak.authentication import AuthenticatorContext, FlowStatus
from mini_keycloak.authentication.providers import ClassProviderFactory
from mini_keycloak.authentication.forms import LoginFormsProvider
from mini_keycloak.authentication.manager import AuthenticationManager
from mini_keycloak.authentication.required_actions import (
    RequiredActionResult,
    RequiredActionRegistry,
    RequiredActionStatus,
)
from mini_keycloak.extensions import db
from mini_keycloak.models import AuthorizationCode, SecurityEvent, UserSession
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.reset_credentials.authenticators import ResetPassword
from mini_keycloak.reset_credentials.update_password import UPDATE_PASSWORD, UpdatePassword
from mini_keycloak.services.authentication_flows import AuthenticationFlowService


def reset_context():
    identities = IdentityRepository(db.session)
    realm = identities.create_realm("required-action-realm")
    client = identities.create_client(
        realm.id, "required-action-client", redirect_uris=["https://client.test/callback"])
    user = identities.create_user(
        realm.id, "required-action-user", "required@example.test", "OriginalPassw0rd!")
    flow = AuthenticationFlowService(db.session).ensure_reset_flow(realm)
    repository = AuthenticationRepository(db.session)
    executions = repository.executions(flow.id)
    auth = repository.create_session(realm, client, client.redirect_uris[0], executions[0].id)
    auth.flow_id = flow.id
    auth.selected_user_id = user.id
    auth.execution_status = {execution.id: "SUCCESS" for execution in executions[:2]}
    provider = ResetPassword()
    context = AuthenticatorContext(repository, auth, realm, client, executions[2], provider)
    return context, user


def test_reset_password_schedules_update_without_changing_credentials(db_app):
    with db_app.app_context():
        context, user = reset_context()

        context.authenticator.authenticate(context)
        result = context.result

        assert result.status == FlowStatus.SUCCESS
        assert result.challenge is None
        assert context.authentication_session.required_actions == [UPDATE_PASSWORD]
        assert context.authentication_session.current_required_action is None
        assert IdentityRepository(db.session).password_matches(user, "OriginalPassw0rd!")
        assert db.session.scalar(select(func.count(UserSession.id))) == 0
        assert db.session.scalar(select(func.count(AuthorizationCode.id))) == 0


def required_action_processor(context, registry=None):
    return AuthenticationManager(
        context.repository,
        context.authentication_session,
        context.realm,
        context.client,
        registry or RequiredActionRegistry(
            {UPDATE_PASSWORD: ClassProviderFactory(UpdatePassword)}
        ),
        forms=LoginFormsProvider(
            context.realm.name, context.authentication_session, "required-action-code"
        ),
    )


def scheduled_context():
    context, user = reset_context()
    context.authenticator.authenticate(context)
    assert context.result.status == FlowStatus.SUCCESS
    return context, user


def test_required_action_challenge_selects_first_pending_provider(db_app):
    with db_app.app_context():
        context, user = scheduled_context()

        outcome = required_action_processor(context).required_action_challenge()

        assert outcome.challenge is not None
        assert (outcome.execution_id, outcome.complete) == (UPDATE_PASSWORD, False)
        assert 'name="password-new"' in outcome.challenge
        assert context.authentication_session.current_required_action == UPDATE_PASSWORD
        assert IdentityRepository(db.session).password_matches(user, "OriginalPassw0rd!")


def test_required_action_policy_failure_remains_pending(db_app):
    with db_app.app_context():
        context, user = scheduled_context()
        context.realm.password_policy = {"clauses": {"length": 14, "digits": 1}}
        processor = required_action_processor(context)
        processor.required_action_challenge()

        outcome = processor.process_required_action(UPDATE_PASSWORD, {
            "password-new": "short",
            "password-confirm": "different",
        })

        assert outcome.challenge is not None and not outcome.complete
        assert "meet realm policy" in outcome.challenge
        assert context.authentication_session.required_actions == [UPDATE_PASSWORD]
        assert context.authentication_session.current_required_action == UPDATE_PASSWORD
        assert IdentityRepository(db.session).password_matches(user, "OriginalPassw0rd!")
        assert db.session.scalar(select(func.count(SecurityEvent.id))) == 0


def test_required_action_success_updates_credential_and_clears_pending_state(db_app):
    with db_app.app_context():
        context, user = scheduled_context()
        processor = required_action_processor(context)
        processor.required_action_challenge()

        outcome = processor.process_required_action(UPDATE_PASSWORD, {
            "password-new": "ReplacementPassw0rd!",
            "password-confirm": "ReplacementPassw0rd!",
        })

        assert outcome.complete and outcome.challenge is None
        assert context.authentication_session.required_actions == []
        assert context.authentication_session.current_required_action is None
        assert IdentityRepository(db.session).password_matches(user, "ReplacementPassw0rd!")
        assert set(db.session.scalars(select(SecurityEvent.event_type))) == {
            "UPDATE_PASSWORD", "UPDATE_CREDENTIAL"}


def test_required_action_rejects_noncurrent_provider(db_app):
    with db_app.app_context():
        context, user = scheduled_context()
        processor = required_action_processor(context)
        processor.required_action_challenge()

        try:
            processor.process_required_action("different-provider", {
                "password-new": "ReplacementPassw0rd!",
                "password-confirm": "ReplacementPassw0rd!",
            })
        except ValueError as error:
            assert str(error) == "Invalid authentication request"
        else:
            raise AssertionError("noncurrent required action was accepted")

        assert context.authentication_session.required_actions == [UPDATE_PASSWORD]
        assert IdentityRepository(db.session).password_matches(user, "OriginalPassw0rd!")


class CompletingRequiredAction:
    def __init__(self, provider_id):
        self.provider_id = provider_id

    def challenge(self, context):
        return RequiredActionResult(
            RequiredActionStatus.CHALLENGE, challenge=self.provider_id
        )

    def action(self, context, form):
        return RequiredActionResult(RequiredActionStatus.SUCCESS)


class RecordingRequiredActionFactory:
    def __init__(self, provider_id, created):
        self.provider_id = provider_id
        self.created = created

    def create(self, session):
        self.created.append(self.provider_id)
        return CompletingRequiredAction(self.provider_id)


def test_required_actions_are_factory_resolved_in_persisted_order(db_app):
    with db_app.app_context():
        context, _ = scheduled_context()
        context.authentication_session.required_actions[:] = ["FIRST", "SECOND"]
        created = []
        registry = RequiredActionRegistry({
            provider_id: RecordingRequiredActionFactory(provider_id, created)
            for provider_id in ("FIRST", "SECOND")
        })
        manager = required_action_processor(context, registry)

        first = manager.required_action_challenge()
        completed_first = manager.process_required_action("FIRST", {})

        assert first.execution_id == "FIRST"
        assert completed_first.execution_id == "SECOND"
        assert context.authentication_session.required_actions == ["SECOND"]
        assert context.authentication_session.current_required_action == "SECOND"
        assert created == ["FIRST", "FIRST", "SECOND"]
