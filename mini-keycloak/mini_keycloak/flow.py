from __future__ import annotations

from mini_keycloak.store import AuthenticationSession, InMemoryStore, User

AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED = "auth.selector.screen.rendered"
ACTION_TOKEN_USER_ID = "action.token.user.id"

CHOOSE_USER_EXECUTION = "choose-user"
EMAIL_GATE_EXECUTION = "email-gate"
UPDATE_PASSWORD_EXECUTION = "update-password"


class FlowStateError(ValueError):
    """The request does not match the current authentication-session state."""


class ResetFlow:
    def __init__(self, store: InMemoryStore) -> None:
        self.store = store

    def create_session(self, client_id: str, redirect_uri: str) -> AuthenticationSession:
        return self.store.create_auth_session(client_id, redirect_uri, CHOOSE_USER_EXECUTION)

    def entry_execution(self, session: AuthenticationSession) -> str | None:
        if session.current_execution == CHOOSE_USER_EXECUTION:
            return CHOOSE_USER_EXECUTION
        # The selector state is stored as a session-level compatibility note.
        selector_displayed = session.auth_notes.get(AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED)
        if selector_displayed and selector_displayed.casefold() == "true":
            return session.current_execution
        return None

    def show_selector(self, session: AuthenticationSession) -> None:
        if session.current_execution != CHOOSE_USER_EXECUTION:
            raise FlowStateError("selector is unavailable for this execution")
        session.auth_notes[AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED] = "true"

    def submit_identifier(self, session: AuthenticationSession, identifier: str) -> None:
        if session.current_execution != CHOOSE_USER_EXECUTION:
            raise FlowStateError("identifier is unavailable for this execution")
        user = self.store.find_user(identifier)
        session.selected_user_id = user.id if user else None
        if user:
            self.store.queue_reset_email(user)
        session.current_execution = EMAIL_GATE_EXECUTION

    def submit_email_gate(self, session: AuthenticationSession) -> User:
        if session.current_execution != EMAIL_GATE_EXECUTION:
            raise FlowStateError("email gate is unavailable for this execution")
        user = self.store.get_user(session.selected_user_id)
        if user is None:
            raise FlowStateError("email gate has no resolved user")
        # This compatibility flow advances after the email-gate action.
        session.password_update_allowed = True
        session.current_execution = UPDATE_PASSWORD_EXECUTION
        return user

    def update_password(self, session: AuthenticationSession, new_password: str) -> User:
        if session.current_execution != UPDATE_PASSWORD_EXECUTION or not session.password_update_allowed:
            raise FlowStateError("password update is not permitted")
        user = self.store.get_user(session.selected_user_id)
        if user is None:
            raise FlowStateError("password update has no resolved user")
        self.store.set_password(user, new_password)
        session.password_update_allowed = False
        return user
