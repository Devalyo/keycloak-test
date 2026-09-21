from urllib.parse import quote, urlsplit

from flask import current_app, jsonify, redirect, request
from sqlalchemy import select
from werkzeug.exceptions import HTTPException

from mini_keycloak.extensions import db
from mini_keycloak.oidc import oidc
from mini_keycloak.oidc.authorization import authorization_redirect
from mini_keycloak.oidc.errors import InvalidClient, InvalidGrant, InvalidRequest, InvalidToken, OAuthError
from mini_keycloak.oidc.token import _credentials, _token_service
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.clients import ClientService
from mini_keycloak.services.sessions import revoke_session
from mini_keycloak.services.events import request_event, request_failure
from mini_keycloak.models import UserSession
from mini_keycloak.security.logging import log_failure


def _logout_parameters():
    if request.args and request.form:
        raise InvalidRequest()
    parameters = request.form if request.method == 'POST' and request.form else request.args
    if any(len(parameters.getlist(name)) != 1 for name in parameters):
        raise InvalidRequest()
    if 'refresh_token' in parameters and (
            request.method != 'POST' or parameters is not request.form
            or any(name in parameters for name in ('id_token_hint', 'post_logout_redirect_uri', 'state'))):
        raise InvalidRequest()
    return parameters


def _logout_identity(realm, parameters):
    service = _token_service()
    if 'refresh_token' in parameters:
        client_id, secret, method = _credentials()
        client = ClientService(db.session).authenticate(realm, client_id, secret=secret, method=method)
        try:
            claims = service.verify_presented(parameters['refresh_token'], realm=realm,
                                             audience=client.client_id, token_type='Refresh')
        except InvalidToken:
            raise InvalidGrant() from None
        return client, claims
    if not parameters.get('id_token_hint'):
        return None, None
    claims = service.verify_logout_hint(parameters['id_token_hint'], realm=realm,
                                       audience=parameters.get('client_id'))
    return IdentityRepository(db.session).get_client(realm.id, claims['azp']), claims


def _post_logout_destination(client, parameters):
    destination = parameters.get('post_logout_redirect_uri')
    if destination not in client.post_logout_redirect_uris:
        return None
    try:
        target = urlsplit(destination)
        if (target.scheme not in {'http', 'https'} or not target.netloc or target.fragment
                or any(character.isspace() for character in destination) or '\\' in destination):
            return None
    except ValueError:
        return None
    state = parameters.get('state')
    return authorization_redirect(destination, {'state': state} if state is not None else {})


@oidc.route('/realms/<realm>/protocol/openid-connect/logout', methods=['GET', 'POST'])
def logout(realm: str):
    enabled_realm = client = None
    try:
        enabled_realm = IdentityRepository(db.session).get_realm(realm)
        if enabled_realm is None or not enabled_realm.enabled:
            response = jsonify(error='invalid_request')
            response.status_code = 404
        else:
            parameters = _logout_parameters()
            client, claims = _logout_identity(enabled_realm, parameters)
            response = jsonify(message='Logout request processed.')
            if claims is not None:
                destination = _post_logout_destination(client, parameters)
                config = current_app.config
                revoke_session(db.session, claims['sid'], enabled_realm.id)
                user_session = db.session.scalar(select(UserSession).where(
                    UserSession.sid == claims['sid'], UserSession.realm_id == enabled_realm.id))
                request_event(db.session, enabled_realm.id, 'LOGOUT', client_id=client.id,
                    user_id=user_session.user_id, user_session_id=user_session.id)
                db.session.commit()
                if 'refresh_token' in parameters:
                    response.status_code = 204
                elif destination is not None:
                    response = redirect(destination)
                # Commit first: failed revocation must leave the browser cookie intact.
                from mini_keycloak.authentication.browser import COOKIE_NAME
                response.delete_cookie(COOKIE_NAME, path=f'/realms/{quote(realm, safe="")}/',
                    httponly=True, samesite='Lax', secure=config['SESSION_COOKIE_SECURE'])
    except OAuthError as error:
        db.session.rollback()
        if enabled_realm is not None:
            request_failure(db.session, realm, 'LOGOUT_ERROR',
                client_id=client.id if client is not None else None, error=error.error)
        response = jsonify(error=error.error)
        response.status_code = error.status_code
        if isinstance(error, InvalidClient):
            response.headers['WWW-Authenticate'] = 'Basic realm="logout"'
    except HTTPException:
        raise
    except Exception:
        db.session.rollback()
        request_failure(db.session, realm, 'LOGOUT_ERROR', error='server_error')
        log_failure('logout')
        response = jsonify(error='server_error')
        response.status_code = 500
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response
