import base64
import binascii
from urllib.parse import unquote_plus

from flask import current_app, jsonify, request
from sqlalchemy import select
from werkzeug.exceptions import HTTPException

from mini_keycloak.extensions import db
from mini_keycloak.oidc import oidc
from mini_keycloak.models import UserSession
from mini_keycloak.oidc.errors import InvalidClient, InvalidRequest, OAuthError, RefreshReuse, UnsupportedGrantType
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.clients import ClientService
from mini_keycloak.services.tokens import TokenService
from mini_keycloak.services.events import request_event, request_failure
from mini_keycloak.security.logging import log_failure
from mini_keycloak.security.login_throttling import CredentialFailure, LoginThrottle


def _credentials():
    form = request.form
    if any(len(form.getlist(name)) > 1 for name in ('client_id', 'client_secret')):
        raise InvalidClient()
    authorization = request.headers.get('Authorization')
    if authorization is not None:
        if 'client_id' in form or 'client_secret' in form:
            raise InvalidClient()
        try:
            scheme, encoded = authorization.split(' ', 1)
            if scheme.lower() != 'basic':
                raise ValueError()
            decoded = base64.b64decode(encoded, validate=True).decode('utf-8')
            client_id, secret = decoded.split(':', 1)
            return unquote_plus(client_id), unquote_plus(secret), 'client_secret_basic'
        except (ValueError, UnicodeError, binascii.Error):
            raise InvalidClient() from None
    return (form.get('client_id', ''), form.get('client_secret'),
            'client_secret_post' if 'client_secret' in form else 'none')


def _token_service():
    config = current_app.config
    return TokenService(db.session, external_url=config['EXTERNAL_URL'],
                        master_secret=config['OIDC_KEY_ENCRYPTION_SECRET'],
                        access_seconds=config['ACCESS_TOKEN_LIFETIME_SECONDS'],
                        refresh_seconds=config['REFRESH_TOKEN_LIFETIME_SECONDS'])


def _password_grant(realm, client):
    config = current_app.config
    return _token_service().password_grant(
        realm=realm, client=client, username=request.form.get('username', ''),
        password=request.form.get('password', ''), scope=request.form.get('scope'),
        throttle=LoginThrottle.from_config(db.session, config), source_address=request.remote_addr,
        dummy_hash=current_app.extensions['browser_dummy_hash'],
        idle_seconds=config['SSO_IDLE_LIFETIME_SECONDS'], max_seconds=config['SSO_MAX_LIFETIME_SECONDS'])


def _authorization_code_grant(realm, client):
    from mini_keycloak.services.authorization import AuthorizationService

    if not request.form.get('code') or not request.form.get('redirect_uri'):
        raise InvalidRequest()
    config = current_app.config
    code = AuthorizationService(db.session, lifetime_seconds=config['AUTHORIZATION_CODE_LIFETIME_SECONDS']).consume(
        request.form['code'], realm_id=realm.id, client_id=client.id,
        redirect_uri=request.form['redirect_uri'], code_verifier=request.form.get('code_verifier'))
    result = _token_service().issue(
        realm=realm, client=client, user_session=db.session.get(UserSession, code.user_session_id),
        scope=code.scope, nonce=code.nonce)
    return result


def _refresh_grant(realm, client):
    if not request.form.get('refresh_token'):
        raise InvalidRequest()
    try:
        return _token_service().refresh(request.form['refresh_token'], realm=realm, client=client,
            scope=request.form.get('scope'), idle_seconds=current_app.config['SSO_IDLE_LIFETIME_SECONDS'])
    except RefreshReuse:
        # Rejection is the successful defensive outcome here: make revocation
        # durable before the outer handler rolls back other rejected grants.
        db.session.commit()
        raise


@oidc.post('/realms/<realm>/protocol/openid-connect/token')
def token(realm: str):
    enabled_realm = client = None
    event_type = 'TOKEN'
    details = {}
    try:
        repository = IdentityRepository(db.session)
        enabled_realm = repository.get_realm(realm)
        if enabled_realm is None or not enabled_realm.enabled:
            response = jsonify(error='invalid_request')
            response.status_code = 404
        else:
            grant_type = request.form.get('grant_type')
            event_type = {'password': 'PASSWORD_GRANT', 'authorization_code': 'CODE_TO_TOKEN',
                          'refresh_token': 'REFRESH_TOKEN'}.get(grant_type, 'TOKEN')
            details = {'grant_type': grant_type}
            client_id, secret, method = _credentials()
            details['auth_method'] = method
            client = ClientService(db.session).authenticate(
                enabled_realm, client_id, secret=secret, method=method)
            if (not request.form.get('grant_type') or any(len(request.form.getlist(name)) > 1
                    for name in ('grant_type', 'code', 'redirect_uri', 'code_verifier',
                                 'username', 'password', 'scope', 'refresh_token'))):
                raise InvalidRequest()
            if request.form.get('grant_type') == 'password':
                response = jsonify(_password_grant(enabled_realm, client))
            elif request.form['grant_type'] == 'authorization_code':
                response = jsonify(_authorization_code_grant(enabled_realm, client))
            elif request.form['grant_type'] == 'refresh_token':
                response = jsonify(_refresh_grant(enabled_realm, client))
            else:
                raise UnsupportedGrantType()
            user_session = db.session.scalar(select(UserSession).where(
                UserSession.sid == response.json['session_state'], UserSession.realm_id == enabled_realm.id))
            request_event(db.session, enabled_realm.id, event_type, client_id=client.id,
                user_id=user_session.user_id, user_session_id=user_session.id, details=details)
            db.session.commit()
    except OAuthError as error:
        db.session.rollback()
        if isinstance(error, CredentialFailure):
            try:
                if not error.blocked:
                    LoginThrottle.from_config(db.session, current_app.config).record_failure(
                        error.realm_id, error.bucket_hash)
                request_event(db.session, error.realm_id, event_type + '_ERROR',
                    client_id=client.id, error=error.error, details=details)
                db.session.commit()
            except Exception:
                db.session.rollback()
                log_failure('token')
                response = jsonify(error='server_error')
                response.status_code = 500
                response.headers['Cache-Control'] = 'no-store'
                response.headers['Pragma'] = 'no-cache'
                return response
        elif enabled_realm is not None and not isinstance(error, RefreshReuse):
            request_failure(db.session, realm, event_type + '_ERROR',
                client_id=client.id if client is not None else None, error=error.error, details=details)
        response = jsonify(error=error.error)
        response.status_code = error.status_code
        if isinstance(error, InvalidClient):
            response.headers['WWW-Authenticate'] = 'Basic realm="token"'
    except HTTPException:
        raise
    except Exception:
        db.session.rollback()
        request_failure(db.session, realm, event_type + '_ERROR', error='server_error', details=details)
        # Exception messages can contain database parameters or key material.
        log_failure('token')
        response = jsonify(error='server_error')
        response.status_code = 500
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response
