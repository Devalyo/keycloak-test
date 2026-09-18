from __future__ import annotations

from collections.abc import Mapping
from html import escape
import secrets
from typing import Any
from urllib.parse import urlencode

from flask import Flask, abort, redirect, request
from sqlalchemy.orm.exc import StaleDataError

from mini_keycloak.authentication import browser
from mini_keycloak.authentication.browser import login_page as _login_page
from mini_keycloak.cli import register_cli
from mini_keycloak.config import Settings
from mini_keycloak.extensions import db, migrate
from mini_keycloak.health import health
from mini_keycloak.flow import (
    CHOOSE_USER_EXECUTION,
    EMAIL_GATE_EXECUTION,
    FlowStateError,
    ResetFlow,
)
from mini_keycloak.models import AuthenticationSession, Realm
from mini_keycloak.oidc import oidc
from mini_keycloak.oidc.hardening import register_hardening
from mini_keycloak.store import PersistentStore
from mini_keycloak.security.passwords import PasswordService
from mini_keycloak.security.logging import RequestCorrelation, configure_access_logging, configure_application_logging
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


def _reset_form(realm: str, session: AuthenticationSession, execution: str) -> str:
    action = _action(realm, "reset-credentials", session, execution)
    username = '<input name="username">' if execution == CHOOSE_USER_EXECUTION else ""
    return _page(
        "Reset credentials",
        f'<form method="post" action="{action}">{username}<button>Continue</button></form>',
    )


def _password_form(realm: str, session: AuthenticationSession) -> str:
    action = _action(realm, "required-action", session, "update-password")
    return _page(
        "Update password",
        f'<form method="post" action="{action}">'
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
    ):
        abort(400, "invalid authentication session")
    return session


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
    flow = ResetFlow(app_store)
    app.extensions["mini_keycloak_store"] = app_store
    app.extensions['browser_dummy_hash'] = PasswordService().hash(secrets.token_urlsafe(32))
    register_cli(app)
    app.register_blueprint(oidc)
    app.register_blueprint(browser)
    app.register_blueprint(health)
    register_hardening(app)

    @app.route("/realms/<realm>/login-actions/reset-credentials", methods=["GET", "POST"])
    def reset_credentials(realm: str):
        enabled_realm = _enabled_realm_or_404(app_store, realm)
        if not enabled_realm.forgot_password_allowed:
            abort(400, "forgot password is disabled")
        session = _request_session(app_store, realm)

        if request.method == "GET":
            execution = flow.entry_execution(session)
            if execution is None:
                return _login_page(realm, session, "Check your email for reset instructions.")
            return _reset_form(realm, session, execution)

        execution = request.args.get("execution", "")
        try:
            if execution == CHOOSE_USER_EXECUTION and "tryAnotherWay" in request.form:
                flow.show_selector(session)
                db.session.commit()
                return _reset_form(realm, session, CHOOSE_USER_EXECUTION)
            if execution == CHOOSE_USER_EXECUTION and "username" in request.form:
                flow.submit_identifier(session, request.form["username"])
                db.session.commit()
                return _login_page(realm, session, "You should receive an email shortly with further instructions.")
            if execution == EMAIL_GATE_EXECUTION:
                flow.submit_email_gate(session)
                db.session.commit()
                return _password_form(realm, session)
        except FlowStateError as exc:
            db.session.rollback()
            abort(400, str(exc))
        except StaleDataError:
            db.session.rollback()
            abort(400, "stale authentication session")
        abort(400, "invalid reset action")

    @app.post("/realms/<realm>/login-actions/required-action")
    def required_action(realm: str):
        _enabled_realm_or_404(app_store, realm)
        if request.args.get("execution") != "update-password":
            abort(400, "invalid required action")
        session = _request_session(app_store, realm)
        new_password = request.form.get("password-new", "")
        confirmation = request.form.get("password-confirm", "")
        if not new_password or new_password != confirmation:
            abort(400, "passwords must be nonempty and match")
        try:
            flow.update_password(session, new_password)
            db.session.commit()
        except FlowStateError as exc:
            db.session.rollback()
            abort(400, str(exc))
        except StaleDataError:
            db.session.rollback()
            abort(400, "stale authentication session")
        location = f"{session.redirect_uri}?{urlencode({'code': secrets.token_urlsafe(18), 'state': 'demo'})}"
        return redirect(location, code=302)

    return app


def main() -> None:
    create_app().run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
