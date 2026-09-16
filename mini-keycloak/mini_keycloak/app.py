from __future__ import annotations

from html import escape
import secrets
from urllib.parse import urlencode

from flask import Flask, abort, jsonify, redirect, request

from mini_keycloak.flow import (
    CHOOSE_USER_EXECUTION,
    EMAIL_GATE_EXECUTION,
    FlowStateError,
    ResetFlow,
)
from mini_keycloak.store import AuthenticationSession, InMemoryStore

REALM = "poc"
CLIENT_ID = "poc-app"
REDIRECT_URI = "http://localhost:9999/callback"


def _action(realm: str, path: str, session: AuthenticationSession, execution: str) -> str:
    query = urlencode(
        {"client_id": session.client_id, "tab_id": session.tab_id, "execution": execution}
    )
    return f"/realms/{escape(realm)}/login-actions/{path}?{query}"


def _page(title: str, body: str) -> str:
    return f"<!doctype html><html><head><title>{escape(title)}</title></head><body>{body}</body></html>"


def _login_page(realm: str, session: AuthenticationSession, message: str = "") -> str:
    action = _action(realm, "authenticate", session, "login")
    return _page(
        "Sign in",
        f"<p>{escape(message)}</p><form method=\"post\" action=\"{action}\">"
        '<input name="username"><input name="password" type="password">'
        "<button>Sign in</button></form>",
    )


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


def _request_session(store: InMemoryStore) -> AuthenticationSession:
    tab_id = request.args.get("tab_id", "")
    session = store.get_auth_session(tab_id)
    if session is None or request.args.get("client_id") != session.client_id:
        abort(400, "invalid authentication session")
    return session


def create_app(store: InMemoryStore | None = None) -> Flask:
    app = Flask(__name__)
    app_store = store or InMemoryStore()
    flow = ResetFlow(app_store)
    app.extensions["mini_keycloak_store"] = app_store

    @app.get("/realms/<realm>/protocol/openid-connect/auth")
    def authorize(realm: str):
        client_id = request.args.get("client_id", "")
        redirect_uri = request.args.get("redirect_uri", "")
        if realm != REALM or client_id != CLIENT_ID or redirect_uri != REDIRECT_URI:
            abort(400, "unknown realm, client, or redirect URI")
        session = flow.create_session(client_id, redirect_uri)
        return _login_page(realm, session)

    @app.route("/realms/<realm>/login-actions/reset-credentials", methods=["GET", "POST"])
    def reset_credentials(realm: str):
        if realm != REALM:
            abort(404)
        session = _request_session(app_store)

        if request.method == "GET":
            execution = flow.entry_execution(session)
            if execution is None:
                return _login_page(realm, session, "Check your email for reset instructions.")
            return _reset_form(realm, session, execution)

        execution = request.args.get("execution", "")
        try:
            if execution == CHOOSE_USER_EXECUTION and "tryAnotherWay" in request.form:
                flow.show_selector(session)
                return _reset_form(realm, session, CHOOSE_USER_EXECUTION)
            if execution == CHOOSE_USER_EXECUTION and "username" in request.form:
                flow.submit_identifier(session, request.form["username"])
                return _login_page(realm, session, "You should receive an email shortly with further instructions.")
            if execution == EMAIL_GATE_EXECUTION:
                flow.submit_email_gate(session)
                return _password_form(realm, session)
        except FlowStateError as exc:
            abort(400, str(exc))
        abort(400, "invalid reset action")

    @app.post("/realms/<realm>/login-actions/required-action")
    def required_action(realm: str):
        if realm != REALM or request.args.get("execution") != "update-password":
            abort(400, "invalid required action")
        session = _request_session(app_store)
        new_password = request.form.get("password-new", "")
        confirmation = request.form.get("password-confirm", "")
        if not new_password or new_password != confirmation:
            abort(400, "passwords must be nonempty and match")
        try:
            flow.update_password(session, new_password)
        except FlowStateError as exc:
            abort(400, str(exc))
        location = f"{session.redirect_uri}?{urlencode({'code': secrets.token_urlsafe(18), 'state': 'poc'})}"
        return redirect(location, code=302)

    @app.post("/realms/<realm>/protocol/openid-connect/token")
    def token(realm: str):
        user = app_store.find_user(request.form.get("username", ""))
        valid = (
            realm == REALM
            and request.form.get("client_id") == CLIENT_ID
            and request.form.get("grant_type") == "password"
            and user is not None
            and app_store.password_matches(user, request.form.get("password", ""))
        )
        if not valid:
            return jsonify(error="invalid_grant"), 401
        return jsonify(
            access_token=secrets.token_urlsafe(24),
            token_type="Bearer",
            expires_in=300,
        )

    @app.get("/debug/outbox")
    def debug_outbox():
        return jsonify(
            [
                {
                    "recipient": message.recipient,
                    "user_id": message.user_id,
                    "action_token": message.action_token,
                    "consumed": message.consumed,
                }
                for message in app_store.outbox
            ]
        )

    return app


def main() -> None:
    create_app().run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
