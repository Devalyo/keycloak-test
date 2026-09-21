from __future__ import annotations

from collections.abc import Mapping
from functools import wraps
import secrets
from typing import Any

from flask import Flask, abort, render_template, request
from sqlalchemy.orm.exc import StaleDataError
from werkzeug.exceptions import HTTPException

from mini_keycloak.authentication import browser
from mini_keycloak.authentication.login_actions import LoginActionsService
from mini_keycloak.cli import register_cli
from mini_keycloak.config import Settings
from mini_keycloak.extensions import db, migrate
from mini_keycloak.health import health
from mini_keycloak.oidc import oidc
from mini_keycloak.oidc.errors import OAuthError
from mini_keycloak.oidc.hardening import register_hardening
from mini_keycloak.store import PersistentStore
from mini_keycloak.security.passwords import PasswordService
from mini_keycloak.security.logging import RequestCorrelation, configure_access_logging, configure_application_logging, log_failure
from mini_keycloak.security.proxy import TrustedProxy


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
        return LoginActionsService(db.session, app_store).reset_credentials(realm)

    @app.get('/realms/<realm>/login-actions/action-token')
    @_reset_errors
    def action_token(realm: str):
        return LoginActionsService(db.session, app_store).action_token(realm)

    @app.post("/realms/<realm>/login-actions/required-action")
    @_reset_errors
    def required_action(realm: str):
        return LoginActionsService(db.session, app_store).required_action(realm)

    return app


def main() -> None:
    create_app().run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
