from __future__ import annotations

from werkzeug.security import generate_password_hash

from mini_keycloak.store import AuthenticationSession, InMemoryStore, ResetState, User


def _eligible(user: User, progress: ResetState | AuthenticationSession) -> bool:
    if not user.email_verified:
        return False
    if isinstance(progress, ResetState):
        if not progress.password_update_allowed:
            return False
    elif progress.auth_notes.get("reset.password.pending") != "true":
        return False
    return True


def apply_password_update(
    store: InMemoryStore,
    progress: ResetState | AuthenticationSession,
    new_password: str,
) -> User:
    if isinstance(progress, ResetState):
        user_id = progress.selected_user_id
    else:
        user_id = progress.auth_notes.get("reset.user")
    user = store.get_user(user_id)
    if user is None:
        raise ValueError("password update has no resolved user")
    if not _eligible(user, progress):
        raise ValueError("password update is not permitted")
    user.password_hash = generate_password_hash(new_password)
    if isinstance(progress, ResetState):
        progress.password_update_allowed = False
    else:
        progress.auth_notes.pop("reset.password.pending", None)
    return user
