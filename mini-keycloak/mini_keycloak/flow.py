from __future__ import annotations

from mini_keycloak.email_action import consume_reset_email, email_action_completed
from mini_keycloak.password_action import apply_password_update
from mini_keycloak.reset_state import ResetSessionState
from mini_keycloak.store import AuthenticationSession, InMemoryStore, User

AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED = "auth.selector.screen.rendered"
CHOOSE_USER_EXECUTION = "choose-user"
EMAIL_GATE_EXECUTION = "email-gate"
UPDATE_PASSWORD_EXECUTION = "update-password"


class FlowStateError(ValueError):
    """The request does not match the current authentication-session state."""


class ResetFlow:
    def __init__(self, store: InMemoryStore, state_mode: str = "notes") -> None:
        self.store = store
        self.state = ResetSessionState(state_mode)

    def create_session(self, client_id: str, redirect_uri: str) -> AuthenticationSession:
        return self.store.create_auth_session(client_id, redirect_uri, CHOOSE_USER_EXECUTION)

    def entry_execution(self, session: AuthenticationSession) -> str | None:
        if session.current_execution == CHOOSE_USER_EXECUTION:
            return CHOOSE_USER_EXECUTION
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
        self.state.select_user(session, user.id if user else None)
        if user:
            self.store.queue_reset_email(user, session.tab_id)
        session.current_execution = EMAIL_GATE_EXECUTION

    def submit_email_gate(self, session: AuthenticationSession) -> User:
        if session.current_execution != EMAIL_GATE_EXECUTION:
            raise FlowStateError("email gate is unavailable for this execution")
        user = self.store.get_user(self.state.selected_user(session))
        if user is None:
            raise FlowStateError("email gate has no resolved user")
        elif not user.email_verified:
            user.email_verified = True
        self.state.allow_password_update(session)
        session.current_execution = UPDATE_PASSWORD_EXECUTION
        return user

    def consume_email_token(self, session: AuthenticationSession, token: str) -> User:
        if session.current_execution != EMAIL_GATE_EXECUTION:
            raise FlowStateError("email action is unavailable for this execution")
        user = self.store.get_user(self.state.selected_user(session))
        if user is None or not consume_reset_email(self.store, session, user.id, token):
            raise FlowStateError("invalid email action")
        if not email_action_completed(self.store, session, user.id):
            raise FlowStateError("email action is incomplete")
        user.email_verified = True
        self.state.record_email_confirmation(session, user.id)
        self.state.allow_password_update(session)
        session.current_execution = UPDATE_PASSWORD_EXECUTION
        return user

    def update_password(self, session: AuthenticationSession, new_password: str) -> User:
        if session.current_execution != UPDATE_PASSWORD_EXECUTION:
            raise FlowStateError("password update is not permitted")
        try:
            progress = session.reset_state if self.state.mode == "typed" else session
            return apply_password_update(self.store, progress, new_password)
        except ValueError as exc:
            raise FlowStateError(str(exc)) from exc
