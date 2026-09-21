"""OpenID Connect protocol endpoints."""

from flask import Blueprint
from werkzeug.exceptions import HTTPException

oidc = Blueprint("oidc", __name__)

from mini_keycloak.oidc import discovery, token, userinfo, logout  # noqa: E402, F401
from mini_keycloak.oidc.hardening import oidc_http_error, unexpected_oidc_error  # noqa: E402

oidc.register_error_handler(HTTPException, oidc_http_error)
oidc.register_error_handler(Exception, unexpected_oidc_error)
