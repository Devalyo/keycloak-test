"""Account selection, reset-message delivery, and password completion."""

from collections.abc import Mapping

from sqlalchemy import select

from mini_keycloak.authentication.engine import AuthenticatorResult, FlowStatus
from mini_keycloak.models import ResetEmail
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.security.password_policy import password_satisfies_policy
from mini_keycloak.services.action_tokens import ResetActionTokenService
from mini_keycloak.services.events import request_event


ATTEMPTED_USERNAME = "attempted.username"
ACTION_TOKEN_USER_ID = "action.token.user.id"
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


def _failure():
    return AuthenticatorResult(FlowStatus.FAILURE, page="error",
                               message="Invalid authentication request", error="invalid_request")


def _event(context, user, event_type):
    request_event(context.repository.session, context.realm.id, event_type,
                  client_id=context.client.id, user_id=user.id,
                  authentication_session_id=context.authentication_session.tab_id)


class ResetCredentialChooseUser:
    def authenticate(self, context):
        return AuthenticatorResult(FlowStatus.CHALLENGE, page="account")

    def action(self, context, form: Mapping[str, str]):
        identifier = form.get("username", "").strip()
        user = IdentityRepository(context.repository.session).find_user(context.realm.id, identifier)
        auth = context.authentication_session
        auth.selected_user_id = user.id if user is not None else None
        auth.password_update_allowed = False
        context.repository.update_session(auth, auth_notes={
            ATTEMPTED_USERNAME: identifier[:320], ACTION_TOKEN_USER_ID: None,
            RESET_EMAIL_DELIVERY: None})
        return AuthenticatorResult(FlowStatus.SUCCESS)


class ResetCredentialEmail:
    def __init__(self, action_tokens: ResetActionTokenService | None = None):
        self.action_tokens = action_tokens

    def authenticate(self, context):
        if _validated_user(context) is not None:
            return AuthenticatorResult(FlowStatus.SUCCESS)
        user = context.user
        if user is not None and user.enabled and user.email:
            auth = context.authentication_session
            delivery = f"{context.execution.id}:{user.id}"
            if auth.auth_notes.get(RESET_EMAIL_DELIVERY) != delivery:
                context.repository.update_session(auth, auth_notes={RESET_EMAIL_DELIVERY: delivery})
                tokens = self.action_tokens or ResetActionTokenService(context.repository.session)
                tokens.issue(auth, user)
                _event(context, user, "SEND_RESET_PASSWORD")
        return AuthenticatorResult(FlowStatus.FORK, page="login", message=RESET_MESSAGE)

    def action(self, context, form: Mapping[str, str]):
        user = context.user
        if user is None or not user.enabled:
            return _failure()
        user.email_verified = True
        return AuthenticatorResult(FlowStatus.SUCCESS)


class ResetPassword:
    def authenticate(self, context):
        user = context.user
        if user is None or not user.enabled:
            return _failure()
        return AuthenticatorResult(FlowStatus.CHALLENGE, page="password")

    def action(self, context, form: Mapping[str, str]):
        user = context.user
        if user is None or not user.enabled:
            return _failure()
        password = form.get("password-new", "")
        policy = context.realm.password_policy
        clauses = policy.get("clauses", {}) if isinstance(policy, Mapping) else None
        if (not password or password != form.get("password-confirm", "")
                or not isinstance(clauses, Mapping)
                or not set(clauses) <= {"length", "digits", "lowerCase", "upperCase", "specialChars"}
                or any(type(minimum) is not int or minimum < 0 for minimum in clauses.values())
                or not password_satisfies_policy(password, clauses)):
            return AuthenticatorResult(FlowStatus.CHALLENGE, page="password",
                                       message="Passwords must match and meet realm policy.")
        IdentityRepository(context.repository.session).set_password(user, password)
        auth = context.authentication_session
        auth.password_update_allowed = False
        context.repository.update_session(auth, auth_notes={ACTION_TOKEN_USER_ID: None})
        _event(context, user, "UPDATE_PASSWORD")
        _event(context, user, "UPDATE_CREDENTIAL")
        return AuthenticatorResult(FlowStatus.SUCCESS)
