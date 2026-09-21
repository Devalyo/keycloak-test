from flask import jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from mini_keycloak.extensions import db
from mini_keycloak.security.logging import log_failure


def unexpected_oidc_error(error):
    # Blueprint-scoped handling runs before Flask's traceback logger, including
    # when TESTING/PROPAGATE_EXCEPTIONS is enabled. Never inspect the exception.
    db.session.rollback()
    log_failure('oidc')
    return jsonify(error='server_error'), 500


def oidc_http_error(error):
    db.session.rollback()
    if error.response is not None:
        return error.response
    return jsonify(error='server_error' if error.code >= 500 else 'invalid_request'), error.code


def register_hardening(app):
    @app.before_request
    def bound_ordinary_request():
        if request.blueprint not in {'browser', 'oidc'}:
            return
        request.max_content_length = 64 * 1024
        request.max_form_memory_size = 64 * 1024
        request.max_form_parts = 64
        if request.content_length is not None and request.content_length > request.max_content_length:
            raise RequestEntityTooLarge()
        # Parse inside this boundary so endpoint catch-all handlers cannot turn
        # HTTP parser failures into a server_error. Bound unknown-length streams too.
        request.get_data()
        request.form

    @app.after_request
    def protocol_headers(response):
        if request.blueprint == 'oidc':
            response.headers.update({'Cache-Control': 'no-store', 'Pragma': 'no-cache',
                'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'})
        if (request.blueprint == 'browser' or
                (request.path.startswith('/realms/') and '/login-actions/' in request.path)):
            response.headers.update({
                'Cache-Control': 'no-store',
                'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
                'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
                'Referrer-Policy': 'no-referrer',
            })
        return response
