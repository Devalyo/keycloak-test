from __future__ import annotations

from mini_keycloak.store import AuthenticationSession


class ResetSessionState:
    def __init__(self, mode: str) -> None:
        if mode not in {"typed", "notes"}:
            raise ValueError("unknown reset state mode")
        self.mode = mode

    def select_user(self, session: AuthenticationSession, user_id: str | None) -> None:
        if self.mode == "typed":
            session.reset_state.selected_user_id = user_id
        elif user_id is None:
            session.auth_notes.pop("reset.user", None)
        else:
            session.auth_notes["reset.user"] = user_id

    def selected_user(self, session: AuthenticationSession) -> str | None:
        if self.mode == "typed":
            return session.reset_state.selected_user_id
        return session.auth_notes.get("reset.user")

    def record_email_confirmation(self, session: AuthenticationSession, user_id: str) -> None:
        if self.mode == "typed":
            session.reset_state.email_confirmed_user_id = user_id
        else:
            session.auth_notes["reset.email.confirmed.user"] = user_id

    def allow_password_update(self, session: AuthenticationSession) -> None:
        if self.mode == "typed":
            session.reset_state.password_update_allowed = True
        else:
            session.auth_notes["reset.password.pending"] = "true"
