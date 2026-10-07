from dataclasses import dataclass

from flask import current_app

from mini_keycloak.authentication.constants import ACTION_TOKEN_USER_ID
from mini_keycloak.models import AuthenticationSession, User
from mini_keycloak.repositories.authentication import AuthenticationRepository


@dataclass(frozen=True)
class ResetProgress:
    selected_user_id: str | None
    action_token_user_id: str | None
    user_enabled: bool
    email_verified: bool
    password_update_allowed: bool
    required_action: str | None


def state_mode() -> str:
    return current_app.config["RESET_STATE_MODE"]


def snapshot(auth: AuthenticationSession, user: User | None) -> ResetProgress:
    return ResetProgress(
        selected_user_id=auth.selected_user_id,
        action_token_user_id=auth.auth_notes.get(ACTION_TOKEN_USER_ID),
        user_enabled=bool(user is not None and user.enabled),
        email_verified=bool(user is not None and user.email_verified),
        password_update_allowed=auth.password_update_allowed,
        required_action=auth.required_actions[0] if auth.required_actions else None,
    )


def schedule_password_update(
    repository: AuthenticationRepository, auth: AuthenticationSession
) -> None:
    if state_mode() == "typed":
        auth.password_update_allowed = True
    else:
        repository.update_session(auth, auth_notes={"reset.password.pending": "true"})


def clear_password_update(
    repository: AuthenticationRepository, auth: AuthenticationSession
) -> None:
    auth.password_update_allowed = False
    repository.update_session(auth, auth_notes={"reset.password.pending": None})
