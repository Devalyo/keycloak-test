from __future__ import annotations

from urllib.parse import quote

from flask import Response, abort, current_app, redirect, request
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from mini_keycloak.authentication.browser import (
    COOKIE_NAME, canonical_origin, preauth_cookie_options,
    validate_stored_authorization,
)
from mini_keycloak.authentication.constants import (
    AUTHENTICATION_FLOW_COMPLETED, CURRENT_AUTHENTICATION_EXECUTION,
    RESET_CREDENTIALS_CHOOSE_USER,
    RESET_CREDENTIAL_EMAIL, RESET_PASSWORD,
)
from mini_keycloak.authentication.engine import AuthenticatorRegistry, FlowOutcome
from mini_keycloak.authentication.processor import AuthenticationProcessor
from mini_keycloak.authentication.forms import LoginFormsProvider
from mini_keycloak.authentication.manager import AuthenticationManager
from mini_keycloak.authentication.providers import (
    ActionTokenHandlerRegistry,
    ClassProviderFactory,
)
from mini_keycloak.authentication.required_actions import (
    RequiredActionRegistry,
)
from mini_keycloak.authentication.session_codes import (
    PREAUTH_COOKIE_PREFIX, SessionCodeChecks,
)
from mini_keycloak.models import AuthenticationSession, Realm, User, UserSession
from mini_keycloak.oidc.authorization import authorization_redirect
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.reset_credentials.action_token import (
    ActionTokenContext,
    ResetCredentialsActionTokenHandler,
)
from mini_keycloak.reset_credentials.authenticators import (
    ResetCredentialChooseUser, ResetCredentialEmail, ResetPassword,
)
from mini_keycloak.reset_credentials.update_password import UPDATE_PASSWORD, UpdatePassword
from mini_keycloak.services.sessions import BrowserAuthenticationResult, UserSessionService
from mini_keycloak.services.action_tokens import ResetActionTokenService
from mini_keycloak.services.authorization import AuthorizationService
from mini_keycloak.services.events import request_event
from mini_keycloak.services.tokens import realm_issuer
from mini_keycloak.security.login_throttling import CredentialFailure, LoginThrottle
from mini_keycloak.store import PersistentStore


AUTHENTICATOR_REGISTRY = AuthenticatorRegistry(
    {
        RESET_CREDENTIALS_CHOOSE_USER: ClassProviderFactory(ResetCredentialChooseUser),
        RESET_CREDENTIAL_EMAIL: ClassProviderFactory(ResetCredentialEmail),
        RESET_PASSWORD: ClassProviderFactory(ResetPassword),
    }
)
REQUIRED_ACTION_REGISTRY = RequiredActionRegistry(
    {UPDATE_PASSWORD: ClassProviderFactory(UpdatePassword)}
)
ACTION_TOKEN_HANDLER_REGISTRY = ActionTokenHandlerRegistry(
    {"reset-credentials": ClassProviderFactory(ResetCredentialsActionTokenHandler)}
)


class LoginActionsService:
    def __init__(self, session: Session, store: PersistentStore | None = None) -> None:
        self.session = session
        self.store = store or PersistentStore(session)

    def _session_service(self) -> UserSessionService:
        return UserSessionService(
            self.session,
            idle_seconds=current_app.config["SSO_IDLE_LIFETIME_SECONDS"],
            max_seconds=current_app.config["SSO_MAX_LIFETIME_SECONDS"],
        )

    def _enabled_realm(self, realm_name: str) -> Realm:
        realm = self.store.get_realm(realm_name)
        if realm is None or not realm.enabled:
            abort(404)
        return realm

    def _processor(
        self, realm: str, authentication_session: AuthenticationSession, session_code: str
    ) -> AuthenticationProcessor:
        return AuthenticationProcessor(
            self.session,
            realm_name=realm,
            client_id=authentication_session.client.client_id,
            tab_id=authentication_session.tab_id,
            registry=AUTHENTICATOR_REGISTRY,
            forms=LoginFormsProvider(realm, authentication_session, session_code),
        )

    def _required_processor(
        self, authentication_session: AuthenticationSession, session_code: str
    ) -> AuthenticationManager:
        return AuthenticationManager(
            AuthenticationRepository(self.session),
            authentication_session,
            authentication_session.realm,
            authentication_session.client,
            REQUIRED_ACTION_REGISTRY,
            forms=LoginFormsProvider(
                authentication_session.realm.name, authentication_session, session_code
            ),
        )

    def _flow_response(
        self,
        realm: str,
        authentication_session: AuthenticationSession,
        outcome: FlowOutcome,
        session_code: str,
    ) -> Response | str:
        forms = LoginFormsProvider(realm, authentication_session, session_code)
        if outcome.complete and authentication_session.required_actions:
            outcome = self._required_processor(
                authentication_session, session_code
            ).required_action_challenge()
        if outcome.complete:
            user = authentication_session.selected_user
            if user is None or not user.enabled:
                abort(400)
            return self.complete_authentication(
                authentication_session, user, commit=False
            )
        if outcome.challenge is not None:
            response = outcome.challenge
        elif outcome.forked:
            response = forms.create_login(outcome.message)
        else:
            abort(400)
        return response

    def authenticate(self, realm: str) -> Response | tuple[str, int]:
        if (
            request.args.get("execution") != "login"
            or any(len(request.args.getlist(key)) != 1 for key in request.args)
            or any(len(request.form.getlist(key)) != 1 for key in request.form)
        ):
            abort(400)
        checks = SessionCodeChecks(self.store)
        try:
            authentication_session = checks.validate(
                realm, "login", require_standard_flow=False
            )
        except ValueError:
            abort(400)
        if (
            authentication_session.client.realm_id
            != authentication_session.realm_id
            or any(
                status == "SUCCESS"
                for status in authentication_session.execution_status.values()
            )
        ):
            abort(400)
        origin = request.headers.get("Origin")
        expected_origin = canonical_origin(
            realm_issuer(
                authentication_session.realm, current_app.config["EXTERNAL_URL"]
            ),
            allow_path=True,
        )
        if (
            origin is not None
            and (expected_origin is None or canonical_origin(origin) != expected_origin)
        ) or request.headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
            abort(400)
        next_code = checks.rotate(authentication_session)
        enabled_realm, client = validate_stored_authorization(
            realm, authentication_session
        )
        throttle = LoginThrottle.from_config(self.session, current_app.config)
        try:
            user, bucket_hash = throttle.authenticate(
                enabled_realm.id,
                request.form.get("username", ""),
                request.form.get("password", ""),
                source_address=request.remote_addr,
                dummy_hash=current_app.extensions["browser_dummy_hash"],
            )
        except StaleDataError:
            self.session.rollback()
            abort(400)
        except CredentialFailure as error:
            if not error.blocked:
                throttle.record_failure(error.realm_id, error.bucket_hash)
            request_event(
                self.session,
                enabled_realm.id,
                "LOGIN_ERROR",
                client_id=client.id,
                error="invalid_credentials",
                details={"reason": "credentials"},
            )
            self.session.commit()
            return (
                LoginFormsProvider(
                    realm, authentication_session, next_code
                ).create_login("Invalid username or password."),
                401,
            )
        try:
            throttle.clear(enabled_realm.id, bucket_hash)
            authentication_session.auth_notes[AUTHENTICATION_FLOW_COMPLETED] = "true"
            return self.complete_authentication(authentication_session, user)
        except StaleDataError:
            self.session.rollback()
            abort(400)

    def complete_authentication(
        self,
        authentication_session: AuthenticationSession,
        user: User,
        *,
        user_session: UserSession | None = None,
        commit: bool = True,
    ) -> Response:
        if authentication_session.required_actions:
            raise ValueError("Invalid authentication request")
        enabled_realm, client = validate_stored_authorization(
            authentication_session.realm.name, authentication_session
        )
        if user_session is None:
            user_session = self._session_service().create(
                enabled_realm, client, user
            )
        result = BrowserAuthenticationResult(authentication_session, user_session)
        code = AuthorizationService(
            self.session,
            lifetime_seconds=current_app.config[
                "AUTHORIZATION_CODE_LIFETIME_SECONDS"
            ],
        ).issue(result)
        request_event(
            self.session,
            authentication_session.realm_id,
            "LOGIN",
            client_id=authentication_session.client_id,
            user_id=user_session.user_id,
            user_session_id=user_session.id,
        )
        if commit:
            self.session.commit()
        parameters = {"code": code}
        if authentication_session.state is not None:
            parameters["state"] = authentication_session.state
        response = redirect(
            authorization_redirect(authentication_session.redirect_uri, parameters)
        )
        serializer = current_app.session_interface.get_signing_serializer(current_app)
        response.set_cookie(
            COOKIE_NAME,
            serializer.dumps({"sid": user_session.sid}),
            httponly=True,
            samesite="Lax",
            secure=current_app.config["SESSION_COOKIE_SECURE"],
            path=f"/realms/{quote(authentication_session.realm.name, safe='')}/",
        )
        response.delete_cookie(
            PREAUTH_COOKIE_PREFIX + authentication_session.tab_id,
            **preauth_cookie_options(authentication_session),
        )
        return response

    def reset_credentials(self, realm: str) -> Response | str:
        enabled_realm = self._enabled_realm(realm)
        if not enabled_realm.forgot_password_allowed:
            abort(400)
        checks = SessionCodeChecks(self.store)
        authentication_session = checks.validate(realm)
        if request.method == "POST":
            expected_execution = authentication_session.auth_notes.get(
                CURRENT_AUTHENTICATION_EXECUTION
            )
            if expected_execution is None:
                raise ValueError("Invalid authentication request")
            authentication_session = checks.validate(realm, expected_execution)
        session_code = checks.rotate(authentication_session)
        processor = self._processor(realm, authentication_session, session_code)
        outcome = (
            processor.process_flow()
            if request.method == "GET"
            else processor.process_action(request.args.get("execution", ""), request.form)
        )
        response = self._flow_response(
            realm, authentication_session, outcome, session_code
        )
        self.session.commit()
        return response

    def _resume_token(
        self, realm: str, authentication_session: AuthenticationSession, session_code: str
    ) -> Response | str:
        processor = self._processor(realm, authentication_session, session_code)
        return self._flow_response(
            realm, authentication_session, processor.process_flow(), session_code
        )

    def action_token(self, realm: str) -> Response:
        self._enabled_realm(realm)
        consumed = ResetActionTokenService(self.session).consume(
            realm, request.args.get("key", "")
        )
        handler = ACTION_TOKEN_HANDLER_REGISTRY.create(
            consumed.token_type, self.session
        )
        response = handler.handle_token(
            ActionTokenContext(
                self.session,
                consumed.authentication_session,
                consumed.user,
                realm,
                self._resume_token,
            )
        )
        self.session.commit()
        return response

    def required_action(self, realm: str) -> Response | str:
        enabled_realm = self._enabled_realm(realm)
        if not enabled_realm.forgot_password_allowed:
            abort(400)
        checks = SessionCodeChecks(self.store)
        authentication_session = checks.validate(realm)
        expected_execution = authentication_session.current_required_action
        if expected_execution is None:
            raise ValueError("Invalid authentication request")
        authentication_session = checks.validate(realm, expected_execution)
        session_code = checks.rotate(authentication_session)
        outcome = self._required_processor(authentication_session, session_code).process_required_action(
            request.args.get("execution", ""), request.form
        )
        response = self._flow_response(
            realm, authentication_session, outcome, session_code
        )
        self.session.commit()
        return response
