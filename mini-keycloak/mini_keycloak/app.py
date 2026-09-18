from __future__ import annotations

from collections.abc import Mapping
from functools import wraps
from html import escape
import secrets
from typing import Any
from urllib.parse import urlencode

from flask import Flask, abort, render_template, request
from sqlalchemy.orm.exc import StaleDataError
from werkzeug.exceptions import HTTPException

from mini_keycloak.authentication import AuthenticationProcessor, AuthenticatorRegistry, browser
from mini_keycloak.authentication.browser import (
    complete_authentication, login_page as _login_page, session_service,
    validate_stored_authorization,
)
from mini_keycloak.authentication.constants import (
    AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED, RESET_CREDENTIALS_CHOOSE_USER,
    RESET_CREDENTIAL_EMAIL, RESET_PASSWORD,
)
from mini_keycloak.cli import register_cli
from mini_keycloak.config import Settings
from mini_keycloak.extensions import db, migrate
from mini_keycloak.health import health
from mini_keycloak.models import AuthenticationSession, Realm
from mini_keycloak.oidc import oidc
from mini_keycloak.oidc.errors import OAuthError
from mini_keycloak.oidc.hardening import register_hardening
from mini_keycloak.store import PersistentStore
from mini_keycloak.reset_credentials.authenticators import (
    ACTION_TOKEN_USER_ID, ResetCredentialChooseUser, ResetCredentialEmail, ResetPassword,
)
from mini_keycloak.services.action_tokens import ResetActionTokenService
from mini_keycloak.services.sessions import BrowserAuthenticationResult
from mini_keycloak.security.passwords import PasswordService
from mini_keycloak.security.logging import RequestCorrelation, configure_access_logging, configure_application_logging, log_failure
from mini_keycloak.security.proxy import TrustedProxy


def _enabled_realm_or_404(store: PersistentStore, realm_name: str) -> Realm:
    realm = store.get_realm(realm_name)
    if realm is None or not realm.enabled:
        abort(404)
    return realm


def _action(realm: str, path: str, session: AuthenticationSession, execution: str) -> str:
    query = urlencode(
        {
            "client_id": session.client.client_id,
            "tab_id": session.tab_id,
            "execution": execution,
        }
    )
    return f"/realms/{escape(realm)}/login-actions/{path}?{query}"


def _page(title: str, body: str) -> str:
    return f"<!doctype html><html><head><title>{escape(title)}</title></head><body>{body}</body></html>"


def _reset_form(realm: str, session: AuthenticationSession, execution: str, *, account: bool) -> str:
    action = _action(realm, "reset-credentials", session, execution)
    username = '<input name="username">' if account else ""
    return _page(
        "Reset credentials",
        f'<form method="post" action="{action}">{username}<button>Continue</button></form>',
    )


def _password_form(realm: str, session: AuthenticationSession, execution: str, message: str) -> str:
    action = _action(realm, "required-action", session, execution)
    return _page(
        "Update password",
        f'<p>{escape(message)}</p><form method="post" action="{action}">'
        '<input name="password-new" type="password">'
        '<input name="password-confirm" type="password">'
        "<button>Save</button></form>",
    )


def _request_session(store: PersistentStore, realm_from_path: str) -> AuthenticationSession:
    tab_id = request.args.get("tab_id", "")
    session = store.get_auth_session(tab_id)
    if (
        session is None
        or session.realm.name != realm_from_path
        or request.args.get("client_id") != session.client.client_id
        or not session.client.enabled
        or not session.client.standard_flow_enabled
        or session.current_execution == 'authenticated'
    ):
        abort(400, "invalid authentication session")
    return session


def _reset_errors(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        try:
            if (any(len(request.args.getlist(key)) != 1 for key in request.args)
                    or any(len(request.form.getlist(key)) != 1 for key in request.form)):
                abort(400)
            return handler(*args, **kwargs)
        except (ValueError, StaleDataError, OAuthError):
            db.session.rollback()
            return render_template('error.html'), 400
        except HTTPException as error:
            db.session.rollback()
            return render_template('error.html'), error.code
        except Exception:
            db.session.rollback()
            log_failure('browser')
            return render_template('error.html'), 500
    return wrapped


def _processor(realm: str, session: AuthenticationSession) -> AuthenticationProcessor:
    if session.current_execution == 'authenticated':
        abort(400)
    return AuthenticationProcessor(db.session, realm_name=realm,
        client_id=session.client.client_id, tab_id=session.tab_id,
        registry=AuthenticatorRegistry({
            RESET_CREDENTIALS_CHOOSE_USER: ResetCredentialChooseUser(),
            RESET_CREDENTIAL_EMAIL: ResetCredentialEmail(),
            RESET_PASSWORD: ResetPassword(),
        }))


def _flow_response(realm: str, processor: AuthenticationProcessor, outcome):
    session = processor.authentication_session
    if outcome.complete:
        enabled_realm, client = validate_stored_authorization(realm, session)
        user = processor.user
        if user is None:
            abort(400)
        user_session = session_service().create(enabled_realm, client, user)
        return complete_authentication(BrowserAuthenticationResult(session, user_session))
    if outcome.page in {'account', 'selector'}:
        execution = processor.repository.get_execution(session.realm_id, outcome.execution_id)
        if execution is None:
            abort(400)
        response = _reset_form(realm, session, outcome.execution_id,
            account=outcome.page == 'account' or execution.authenticator == RESET_CREDENTIALS_CHOOSE_USER)
    elif outcome.page == 'login':
        response = _login_page(realm, session, outcome.message)
    elif outcome.page == 'password':
        response = _password_form(realm, session, outcome.execution_id, outcome.message)
    else:
        abort(400)
    db.session.commit()
    return response


def create_app(config: Mapping[str, Any] | None = None) -> Flask:
    settings = Settings.from_env(overrides=config)
    flask_config = settings.as_flask_config(overrides=config)
    configure_access_logging()
    app = Flask(__name__)
    app.config.from_mapping(flask_config)
    configure_application_logging(app)
    app.wsgi_app = TrustedProxy(app.wsgi_app, mode=settings.proxy_mode,
                               cidrs=settings.trusted_proxy_cidrs, hops=settings.proxy_hops,
                               hosts=settings.trusted_hosts)
    app.wsgi_app = RequestCorrelation(app.wsgi_app)
    db.init_app(app)
    migrate.init_app(app, db)
    app_store = PersistentStore(db.session)
    app.extensions["mini_keycloak_store"] = app_store
    app.extensions['browser_dummy_hash'] = PasswordService().hash(secrets.token_urlsafe(32))
    register_cli(app)
    app.register_blueprint(oidc)
    app.register_blueprint(browser)
    app.register_blueprint(health)
    register_hardening(app)

    @app.route("/realms/<realm>/login-actions/reset-credentials", methods=["GET", "POST"])
    @_reset_errors
    def reset_credentials(realm: str):
        enabled_realm = _enabled_realm_or_404(app_store, realm)
        if not enabled_realm.forgot_password_allowed:
            abort(400, "forgot password is disabled")
        session = _request_session(app_store, realm)
        processor = _processor(realm, session)
        if request.method == "GET":
            outcome = processor.process_flow()
        else:
            outcome = processor.process_action(request.args.get('execution', ''), request.form)
        return _flow_response(realm, processor, outcome)

    @app.get('/realms/<realm>/login-actions/action-token')
    @_reset_errors
    def action_token(realm: str):
        session, user = ResetActionTokenService(db.session).consume(realm, request.args.get('key', ''))
        processor = _processor(realm, session)
        session.selected_user_id = user.id
        processor.repository.update_session(session, auth_notes={
            ACTION_TOKEN_USER_ID: user.id, AUTHENTICATION_SELECTOR_SCREEN_DISPLAYED: None})
        return _flow_response(realm, processor, processor.process_flow())

    @app.post("/realms/<realm>/login-actions/required-action")
    @_reset_errors
    def required_action(realm: str):
        enabled_realm = _enabled_realm_or_404(app_store, realm)
        if not enabled_realm.forgot_password_allowed:
            abort(400)
        session = _request_session(app_store, realm)
        processor = _processor(realm, session)
        return _flow_response(realm, processor,
            processor.process_action(request.args.get('execution', ''), request.form))

    return app


def main() -> None:
    create_app().run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
