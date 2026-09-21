"""Account selection, reset-message delivery, and password completion."""

from collections.abc import Mapping

from sqlalchemy import select

from mini_keycloak.authentication.constants import ACTION_TOKEN_USER_ID
from mini_keycloak.models import ResetEmail
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.action_tokens import ResetActionTokenService
from mini_keycloak.services.events import request_event
from mini_keycloak.reset_credentials.update_password import UPDATE_PASSWORD


ATTEMPTED_USERNAME = "attempted.username"
RESET_EMAIL_DELIVERY = "reset.email.delivery"
RESET_MESSAGE = "If the account exists, reset instructions have been sent."


def _validated_user(context):
    auth, user = context.authentication_session, context.user
    if (user is None or not user.enabled
            or auth.auth_notes.get(ACTION_TOKEN_USER_ID) != user.id):
        return None
    message = context.repository.session.scalar(select(ResetEmail.id).where(
        ResetEmail.realm_id == context.realm.id,
        ResetEmail.client_id == context.client.id,
        ResetEmail.authentication_session_id == auth.tab_id,
        ResetEmail.user_id == user.id,
        ResetEmail.consumed_at.is_not(None),
        ResetEmail.consumed.is_(True),
    ).limit(1))
    return user if message is not None else None


def _failure(context):
    context.failure(message="Invalid authentication request")


def _event(context, user, event_type):
    request_event(context.repository.session, context.realm.id, event_type,
                  client_id=context.client.id, user_id=user.id,
                  authentication_session_id=context.authentication_session.tab_id)


class ResetCredentialChooseUser:
    def authenticate(self, context):
        if context.form is None:
            _failure(context)
            return
        context.challenge(context.form.create_password_reset(account=True))

    def action(self, context, form: Mapping[str, str]):
        identifier = form.get("username", "").strip()
        user = IdentityRepository(context.repository.session).find_user(context.realm.id, identifier)
        auth = context.authentication_session
        auth.selected_user_id = user.id if user is not None else None
        auth.password_update_allowed = False
        context.repository.update_session(auth, auth_notes={
            ATTEMPTED_USERNAME: identifier[:320], ACTION_TOKEN_USER_ID: None,
            RESET_EMAIL_DELIVERY: None})
        context.success()


class ResetCredentialEmail:
    def __init__(self, action_tokens: ResetActionTokenService | None = None):
        self.action_tokens = action_tokens

    def authenticate(self, context):
        if _validated_user(context) is not None:
            context.success()
            return
        user = context.user
        if user is not None and user.enabled and user.email:
            auth = context.authentication_session
            delivery = f"{context.execution.id}:{user.id}"
            if auth.auth_notes.get(RESET_EMAIL_DELIVERY) != delivery:
                context.repository.update_session(auth, auth_notes={RESET_EMAIL_DELIVERY: delivery})
                tokens = self.action_tokens or ResetActionTokenService(context.repository.session)
                tokens.issue(auth, user)
                _event(context, user, "SEND_RESET_PASSWORD")
        context.fork(RESET_MESSAGE)

    def action(self, context, form: Mapping[str, str]):
        user = context.user
        if user is None or not user.enabled:
            _failure(context)
            return
        user.email_verified = True
        context.success()


class ResetPassword:
    def authenticate(self, context):
        user = context.user
        if user is None or not user.enabled:
            _failure(context)
            return
        auth = context.authentication_session
        if UPDATE_PASSWORD not in auth.required_actions:
            auth.required_actions.append(UPDATE_PASSWORD)
        context.success()

    def action(self, context, form: Mapping[str, str]):
        self.authenticate(context)
