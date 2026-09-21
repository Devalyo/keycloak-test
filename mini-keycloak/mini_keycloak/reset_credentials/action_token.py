from collections.abc import Callable
from dataclasses import dataclass

from flask import Response, make_response
from sqlalchemy.orm import Session

from mini_keycloak.authentication.browser import preauth_cookie_options
from mini_keycloak.authentication.constants import (
    ACTION_TOKEN_USER_ID,
    AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED,
)
from mini_keycloak.authentication.session_codes import (
    PREAUTH_COOKIE_PREFIX,
    SessionContinuation,
    browser_binding,
)
from mini_keycloak.models import AuthenticationSession, User
from mini_keycloak.repositories.authentication import AuthenticationRepository


@dataclass(frozen=True)
class ActionTokenContext:
    session: Session
    authentication_session: AuthenticationSession
    user: User
    realm_name: str
    resume: Callable[[str, AuthenticationSession, str], Response | str]


class ResetCredentialsActionTokenHandler:
    def handle_token(self, context: ActionTokenContext) -> Response:
        authentication_session = context.authentication_session
        authentication_session.selected_user_id = context.user.id
        AuthenticationRepository(context.session).update_session(
            authentication_session,
            auth_notes={
                ACTION_TOKEN_USER_ID: context.user.id,
                AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED: None,
            },
        )
        authentication_session.browser_binding_generation += 1
        session_code = SessionContinuation.replace(authentication_session)
        response = make_response(
            context.resume(
                context.realm_name, authentication_session, session_code
            )
        )
        response.set_cookie(
            PREAUTH_COOKIE_PREFIX + authentication_session.tab_id,
            browser_binding(authentication_session),
            max_age=1800,
            **preauth_cookie_options(authentication_session),
        )
        return response
