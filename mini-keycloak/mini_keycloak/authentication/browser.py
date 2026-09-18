from datetime import timedelta
import hmac
from ipaddress import IPv6Address
import re
import secrets
from urllib.parse import quote, urlencode, urlsplit

from flask import Blueprint, abort, current_app, make_response, redirect, render_template, request
from itsdangerous import BadData
from sqlalchemy.orm.exc import StaleDataError
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import HTTPException

from mini_keycloak.extensions import db
from mini_keycloak.authentication.constants import AUTHENTICATION_FLOW_COMPLETED
from mini_keycloak.models import AuthenticationSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.oidc.authorization import authorization_error, authorization_redirect
from mini_keycloak.oidc.errors import InvalidRequest, OAuthError, UnauthorizedClient
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.sessions import BrowserAuthenticationResult, UserSessionService
from mini_keycloak.services.tokens import realm_issuer
from mini_keycloak.services.authorization import AuthorizationService
from mini_keycloak.services.authentication_flows import AuthenticationFlowService
from mini_keycloak.services.events import request_event, request_failure
from mini_keycloak.security.logging import log_failure
from mini_keycloak.security.login_throttling import CredentialFailure, LoginThrottle


browser = Blueprint('browser', __name__)
COOKIE_NAME = 'mini_keycloak_session'
PREAUTH_COOKIE_PREFIX = 'mini_keycloak_login_'
SUPPORTED_SCOPES = {'openid', 'profile', 'email'}
OIDC_FIELDS = ('redirect_uri', 'response_type', 'scope', 'state', 'nonce',
               'code_challenge', 'code_challenge_method')


def session_service():
    return UserSessionService(db.session,
        idle_seconds=current_app.config['SSO_IDLE_LIFETIME_SECONDS'],
        max_seconds=current_app.config['SSO_MAX_LIFETIME_SECONDS'])


def login_page(realm, session, message=''):
    path = f'/realms/{quote(realm, safe="")}/login-actions/'
    params = dict(client_id=session.client.client_id, tab_id=session.tab_id)
    return render_template('login.html',
        display_name=session.realm.display_name or realm, message=message,
        action=path + 'authenticate?' + urlencode(params | {'execution': 'login'}),
        reset_url=path + 'reset-credentials?' + urlencode(params),
        forgot_password_allowed=session.realm.forgot_password_allowed)


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
    secret = current_app.secret_key
    if isinstance(secret, str):
        secret = secret.encode()
    binding = f'mini-keycloak:preauth:v1\0{session.realm_id}\0{session.tab_id}'.encode()
    return hmac.new(secret, binding, 'sha256').hexdigest()


def preauth_cookie_options(session):
    # One cookie per tab preserves independent login forms. Restrict its path
    # to ordinary authentication so it is not sent to reset actions.
    return dict(httponly=True, samesite='Lax',
        secure=current_app.config['SESSION_COOKIE_SECURE'],
        path=f'/realms/{quote(session.realm.name, safe="")}/login-actions/authenticate')


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


def complete_authentication(result: BrowserAuthenticationResult):
    """Commit browser authentication and its authorization code together."""
    code = AuthorizationService(db.session,
        lifetime_seconds=current_app.config['AUTHORIZATION_CODE_LIFETIME_SECONDS']).issue(result)
    request_event(db.session, result.authentication_session.realm_id, 'LOGIN',
        client_id=result.authentication_session.client_id, user_id=result.user_session.user_id,
        user_session_id=result.user_session.id)
    db.session.commit()
    parameters = {'code': code}
    if result.authentication_session.state is not None:
        parameters['state'] = result.authentication_session.state
    response = redirect(authorization_redirect(result.authentication_session.redirect_uri, parameters))
    serializer = current_app.session_interface.get_signing_serializer(current_app)
    response.set_cookie(COOKIE_NAME, serializer.dumps({'sid': result.user_session.sid}),
        httponly=True, samesite='Lax', secure=current_app.config['SESSION_COOKIE_SECURE'],
        path=f'/realms/{quote(result.authentication_session.realm.name, safe="")}/')
    response.delete_cookie(PREAUTH_COOKIE_PREFIX + result.authentication_session.tab_id,
        **preauth_cookie_options(result.authentication_session))
    return response


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
    sid = browser_sid()
    user_session = session_service().reuse(sid, enabled_realm) if sid else None
    if user_session is not None:
        session.auth_notes[AUTHENTICATION_FLOW_COMPLETED] = 'true'
        return complete_authentication(BrowserAuthenticationResult(session, user_session))
    db.session.commit()
    response = make_response(login_page(realm, session))
    response.set_cookie(PREAUTH_COOKIE_PREFIX + session.tab_id, preauth_token(session),
        max_age=1800, **preauth_cookie_options(session))
    return response


@browser.post('/realms/<realm>/login-actions/authenticate')
def authenticate(realm):
    if (request.args.get('execution') != 'login'
            or any(len(request.args.getlist(key)) != 1 for key in request.args)
            or any(len(request.form.getlist(key)) != 1 for key in request.form)):
        abort(400)
    session = AuthenticationRepository(db.session).get_session(request.args.get('tab_id', ''))
    if (session is None or session.realm.name != realm
            or session.client.realm_id != session.realm_id
            or session.client.client_id != request.args.get('client_id')
            or session.current_execution == 'authenticated'
            or any(status == 'SUCCESS' for status in session.execution_status.values())):
        abort(400)
    # Browser hints add defense in depth to the mandatory pre-auth cookie.
    # Only trusted realm/configuration state selects the accepted origin.
    origin = request.headers.get('Origin')
    expected_origin = canonical_origin(
        realm_issuer(session.realm, current_app.config['EXTERNAL_URL']), allow_path=True)
    if ((origin is not None and (expected_origin is None or canonical_origin(origin) != expected_origin))
            or request.headers.get('Sec-Fetch-Site') not in (None, 'same-origin')):
        abort(400)
    supplied_token = request.cookies.get(PREAUTH_COOKIE_PREFIX + session.tab_id, '')
    if not hmac.compare_digest(supplied_token.encode(), preauth_token(session).encode()):
        abort(400)
    enabled_realm, client = validate_stored_authorization(realm, session)
    throttle = LoginThrottle.from_config(db.session, current_app.config)
    try:
        user, bucket_hash = throttle.authenticate(enabled_realm.id, request.form.get('username', ''),
            request.form.get('password', ''), source_address=request.remote_addr,
            dummy_hash=current_app.extensions['browser_dummy_hash'])
    except CredentialFailure as error:
        if not error.blocked:
            throttle.record_failure(error.realm_id, error.bucket_hash)
        request_event(db.session, enabled_realm.id, 'LOGIN_ERROR', client_id=client.id,
                      error='invalid_credentials', details={'reason': 'credentials'})
        db.session.commit()
        return login_page(realm, session, 'Invalid username or password.'), 401
    try:
        throttle.clear(enabled_realm.id, bucket_hash)
        user_session = session_service().create(enabled_realm, client, user)
        session.auth_notes[AUTHENTICATION_FLOW_COMPLETED] = 'true'
        return complete_authentication(BrowserAuthenticationResult(session, user_session))
    except StaleDataError:
        db.session.rollback()
        abort(400)


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


@browser.errorhandler(Exception)
def unexpected_browser_error(error):
    db.session.rollback()
    request_failure(db.session, request.view_args['realm'], 'LOGIN_ERROR', error='server_error')
    log_failure('browser')
    return render_template('error.html'), 500
