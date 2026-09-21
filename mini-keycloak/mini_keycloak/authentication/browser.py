from datetime import timedelta
from ipaddress import IPv6Address
import re
import secrets
from urllib.parse import quote, urlsplit

from flask import Blueprint, abort, current_app, make_response, render_template, request
from itsdangerous import BadData
from sqlalchemy.orm.exc import StaleDataError
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import HTTPException

from mini_keycloak.extensions import db
from mini_keycloak.authentication.constants import AUTHENTICATION_FLOW_COMPLETED
from mini_keycloak.authentication.forms import LoginFormsProvider
from mini_keycloak.authentication.session_codes import (
    PREAUTH_COOKIE_PREFIX, SessionContinuation, browser_binding,
)
from mini_keycloak.models import AuthenticationSession, User
from mini_keycloak.models.identity import utc_now
from mini_keycloak.oidc.authorization import authorization_error
from mini_keycloak.oidc.errors import InvalidRequest, OAuthError, UnauthorizedClient
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.sessions import UserSessionService
from mini_keycloak.services.authentication_flows import AuthenticationFlowService
from mini_keycloak.services.events import request_failure
from mini_keycloak.security.logging import log_failure


browser = Blueprint('browser', __name__)
COOKIE_NAME = 'mini_keycloak_session'
SUPPORTED_SCOPES = {'openid', 'profile', 'email'}
OIDC_FIELDS = ('redirect_uri', 'response_type', 'scope', 'state', 'nonce',
               'code_challenge', 'code_challenge_method')


def session_service():
    return UserSessionService(db.session,
        idle_seconds=current_app.config['SSO_IDLE_LIFETIME_SECONDS'],
        max_seconds=current_app.config['SSO_MAX_LIFETIME_SECONDS'])


def login_page(realm, session, session_code, message=''):
    return LoginFormsProvider(realm, session, session_code).create_login(message)


def validate_authorization(realm_name, args):
    if any(len(args.getlist(key)) != 1 for key in args):
        raise InvalidRequest()
    identities = IdentityRepository(db.session)
    realm = identities.get_realm(realm_name)
    if realm is None or not realm.enabled:
        abort(404)
    client = identities.get_client(realm.id, args.get('client_id', ''))
    if client is None or not client.enabled:
        raise UnauthorizedClient()
    redirect_uri = args.get('redirect_uri')
    if redirect_uri not in client.redirect_uris or urlsplit(redirect_uri).fragment:
        raise InvalidRequest()
    destination = dict(redirect_uri=redirect_uri, state=args.get('state'))
    if not client.standard_flow_enabled:
        raise UnauthorizedClient(**destination)
    # Unsupported options must not silently skip required credential entry.
    if 'prompt' in args or 'max_age' in args or args.get('response_type') != 'code':
        raise InvalidRequest(**destination)
    scopes = set(args.get('scope', '').split())
    if ('openid' not in scopes or not scopes <= SUPPORTED_SCOPES
            or not scopes <= set(client.default_scopes + client.optional_scopes)):
        raise InvalidRequest(**destination)
    challenge, method = args.get('code_challenge'), args.get('code_challenge_method')
    if client.pkce_policy not in {'S256', 'optional'}:
        raise InvalidRequest(**destination)
    if client.pkce_policy == 'S256' or challenge is not None or method is not None:
        if method != 'S256' or re.fullmatch(r'[A-Za-z0-9_-]{43}', challenge or '') is None:
            raise InvalidRequest(**destination)
    return realm, client


def validate_stored_authorization(realm_name, session):
    """Revalidate the original request against current realm and client policy."""
    parameters = {name: getattr(session, name) for name in OIDC_FIELDS}
    parameters['client_id'] = session.client.client_id
    return validate_authorization(realm_name, MultiDict(
        {key: value for key, value in parameters.items() if value is not None}))


def browser_sid():
    serializer = current_app.session_interface.get_signing_serializer(current_app)
    try:
        payload = serializer.loads(request.cookies.get(COOKIE_NAME, ''))
    except BadData:
        return None
    if not isinstance(payload, dict) or set(payload) != {'sid'} or not isinstance(payload['sid'], str):
        return None
    return payload['sid']


def preauth_token(session):
    """Opaque proof that this browser received this realm's login transaction."""
    return browser_binding(session)


def preauth_cookie_options(session):
    # One cookie per tab preserves independent login forms across login actions.
    return dict(httponly=True, samesite='Lax',
        secure=current_app.config['SESSION_COOKIE_SECURE'],
        path=f'/realms/{quote(session.realm.name, safe="")}/login-actions/')


def canonical_origin(value, *, allow_path=False):
    """Parse an HTTP origin strictly; issuer paths do not participate in trust."""
    if any(character.isspace() or ord(character) < 32 for character in value):
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {'http', 'https'}
                or re.fullmatch(r'(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]+)?', parsed.netloc) is None
                or '?' in value or '#' in value or (parsed.path and not allow_path)):
            return None
        host = parsed.hostname
        if ':' in host:
            host = IPv6Address(host).compressed
        port = parsed.port if parsed.port is not None else {'http': 80, 'https': 443}[parsed.scheme]
        return parsed.scheme, host, port
    except ValueError:
        return None


@browser.get('/realms/<realm>/protocol/openid-connect/auth')
def authorize(realm):
    enabled_realm, client = validate_authorization(realm, request.args)
    flows = AuthenticationFlowService(db.session)
    flow = flows.ensure_reset_flow(enabled_realm)
    executions = flows.executions(flow.id)
    if not executions:
        raise InvalidRequest()
    session = AuthenticationSession(
        tab_id=secrets.token_urlsafe(18), realm_id=enabled_realm.id, client_id=client.id,
        flow_id=flow.id, current_execution=executions[0].id, execution_status={},
        expires_at=utc_now() + timedelta(minutes=30),
        **{name: request.args.get(name) for name in OIDC_FIELDS})
    db.session.add(session)
    db.session.flush()
    session_code = SessionContinuation.issue(session)
    sid = browser_sid()
    user_session = session_service().reuse(sid, enabled_realm) if sid else None
    if user_session is not None:
        session.auth_notes[AUTHENTICATION_FLOW_COMPLETED] = 'true'
        user = db.session.get(User, user_session.user_id)
        if user is None or not user.enabled:
            abort(400)
        from mini_keycloak.authentication.login_actions import LoginActionsService
        return LoginActionsService(db.session).complete_authentication(
            session, user, user_session=user_session
        )
    db.session.commit()
    response = make_response(login_page(realm, session, session_code))
    response.set_cookie(PREAUTH_COOKIE_PREFIX + session.tab_id, preauth_token(session),
        max_age=1800, **preauth_cookie_options(session))
    return response


@browser.post('/realms/<realm>/login-actions/authenticate')
def authenticate(realm):
    from mini_keycloak.authentication.login_actions import LoginActionsService
    return LoginActionsService(db.session).authenticate(realm)


@browser.errorhandler(HTTPException)
def browser_error(error):
    db.session.rollback()
    request_failure(db.session, request.view_args['realm'], 'LOGIN_ERROR', error='invalid_request')
    return render_template('error.html'), error.code


@browser.errorhandler(OAuthError)
def oauth_error(error):
    db.session.rollback()
    request_failure(db.session, request.view_args['realm'], 'LOGIN_ERROR', error=error.error)
    return authorization_error(error)


@browser.errorhandler(StaleDataError)
def stale_browser_transition(error):
    db.session.rollback()
    request_failure(db.session, request.view_args['realm'], 'LOGIN_ERROR', error='invalid_request')
    return render_template('error.html'), 400


@browser.errorhandler(Exception)
def unexpected_browser_error(error):
    db.session.rollback()
    request_failure(db.session, request.view_args['realm'], 'LOGIN_ERROR', error='server_error')
    log_failure('browser')
    return render_template('error.html'), 500
