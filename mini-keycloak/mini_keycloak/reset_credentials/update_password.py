from collections.abc import Mapping

from mini_keycloak.authentication.constants import ACTION_TOKEN_USER_ID
from mini_keycloak.authentication.required_actions import (
    RequiredActionContext,
    RequiredActionResult,
    RequiredActionStatus,
)
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.reset_credentials.progress import (
    ResetProgress, clear_password_update, snapshot, state_mode,
)
from mini_keycloak.security.password_policy import password_satisfies_policy
from mini_keycloak.services.events import request_event


UPDATE_PASSWORD = "UPDATE_PASSWORD"


def _failure() -> RequiredActionResult:
    return RequiredActionResult(
        RequiredActionStatus.FAILURE,
        message="Invalid authentication request",
    )


def _eligible_typed(progress: ResetProgress, provider_id: str) -> bool:
    if not progress.user_enabled or not progress.email_verified:
        return False
    if progress.required_action != provider_id:
        return False
    if not progress.password_update_allowed:
        return False
    return True


def _eligible(context: RequiredActionContext) -> bool:
    auth = context.authentication_session
    user = context.user
    if state_mode() == "typed":
        return _eligible_typed(snapshot(auth, user), context.provider_id)
    if user is None or not user.enabled or not user.email_verified:
        return False
    if not auth.required_actions or auth.required_actions[0] != context.provider_id:
        return False
    if auth.auth_notes.get("reset.password.pending") != "true":
        return False
    return True


class UpdatePassword:
    def challenge(self, context: RequiredActionContext) -> RequiredActionResult:
        if not _eligible(context):
            return _failure()
        if context.form is None:
            return _failure()
        return RequiredActionResult(
            RequiredActionStatus.CHALLENGE,
            challenge=context.form.create_update_password(),
        )

    def action(
        self, context: RequiredActionContext, form: Mapping[str, str]
    ) -> RequiredActionResult:
        if not _eligible(context):
            return _failure()
        password = form.get("password-new", "")
        policy = context.realm.password_policy
        clauses = policy.get("clauses", {}) if isinstance(policy, Mapping) else None
        if (
            not password
            or password != form.get("password-confirm", "")
            or not isinstance(clauses, Mapping)
            or not set(clauses)
            <= {"length", "digits", "lowerCase", "upperCase", "specialChars"}
            or any(type(minimum) is not int or minimum < 0 for minimum in clauses.values())
            or not password_satisfies_policy(password, clauses)
        ):
            return RequiredActionResult(
                RequiredActionStatus.CHALLENGE,
                challenge=context.form.create_update_password(
                    "Passwords must match and meet realm policy."
                ) if context.form is not None else None,
                message="Passwords must match and meet realm policy.",
            )
        user = context.user
        IdentityRepository(context.repository.session).set_password(user, password)
        auth = context.authentication_session
        clear_password_update(context.repository, auth)
        context.repository.update_session(auth, auth_notes={ACTION_TOKEN_USER_ID: None})
        for event_type in ("UPDATE_PASSWORD", "UPDATE_CREDENTIAL"):
            request_event(
                context.repository.session,
                context.realm.id,
                event_type,
                client_id=context.client.id,
                user_id=user.id,
                authentication_session_id=auth.tab_id,
            )
        return RequiredActionResult(RequiredActionStatus.SUCCESS)
