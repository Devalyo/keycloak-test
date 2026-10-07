import json
import re
import shlex

from flask import Blueprint, current_app, jsonify, request, url_for
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException

from mini_keycloak.extensions import db
from mini_keycloak.import_export.validation import RealmImportValidationError, validate_realm_import
from mini_keycloak.models import (
    AuthenticationFlow, AuthorizationCode, Client, Realm, RefreshToken, UserSession,
)
from mini_keycloak.models.identity import utc_now
from mini_keycloak.oidc.errors import OAuthError
from mini_keycloak.oidc.token import _token_service
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.security.logging import log_failure
from mini_keycloak.services.admin_management import delete_client, delete_realm
from mini_keycloak.services.authentication_flows import AuthenticationFlowService
from mini_keycloak.services.realm_import import (
    ClientAlreadyExists, RealmAlreadyExists, RealmImportError, RealmImportService,
)


admin = Blueprint('admin', __name__)


class AdminError(Exception):
    def __init__(self, status_code: int, error: str):
        self.status_code = status_code
        self.error = error


def _realm_representation(realm: Realm) -> dict:
    flow = db.session.get(AuthenticationFlow, realm.reset_credentials_flow_id)
    return {
        'id': realm.id,
        'realm': realm.name,
        'displayName': realm.display_name,
        'enabled': realm.enabled,
        'resetPasswordAllowed': realm.forgot_password_allowed,
        'resetCredentialsFlow': flow.alias if flow is not None else None,
        'passwordPolicy': realm.password_policy.get('raw', ''),
        'smtpServer': realm.smtp_server,
        'accessTokenLifespan': realm.access_token_lifetime_seconds,
        'accessCodeLifespan': realm.authorization_code_lifetime_seconds,
        'ssoSessionIdleTimeout': realm.sso_idle_lifetime_seconds,
        'ssoSessionMaxLifespan': realm.sso_max_lifetime_seconds,
        'attributes': {'mini.keycloak.passwordGrantEnabled':
                       str(realm.password_grant_enabled).lower()},
    }


def _client_representation(client: Client) -> dict:
    return {
        'id': client.id,
        'clientId': client.client_id,
        'name': client.name,
        'enabled': client.enabled,
        'publicClient': client.public_client,
        'redirectUris': client.redirect_uris,
        'webOrigins': client.web_origins,
        'standardFlowEnabled': client.standard_flow_enabled,
        'directAccessGrantsEnabled': client.direct_access_grants_enabled,
        'defaultClientScopes': client.default_scopes,
        'optionalClientScopes': client.optional_scopes,
        'attributes': {
            'pkce.code.challenge.method': client.pkce_policy,
            'post.logout.redirect.uris': '##'.join(client.post_logout_redirect_uris),
        },
    }


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError()


def _body() -> dict:
    if request.mimetype != 'application/json':
        raise AdminError(415, 'unsupported_media_type')
    try:
        value = json.loads(request.get_data(), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise AdminError(400, 'invalid_request') from None
    if type(value) is not dict:
        raise AdminError(400, 'invalid_request')
    return value


def _validated(document: dict, *, update: bool):
    try:
        return validate_realm_import(document, update=update).value
    except RealmImportValidationError:
        raise AdminError(400, 'invalid_request') from None


def _import(value, *, update=False, create_only_clients=False):
    try:
        result = RealmImportService(
            db.session, current_app.config['OIDC_KEY_ENCRYPTION_SECRET']
        ).import_realm(value, update=update, create_only_clients=create_only_clients)
        db.session.commit()
        return result
    except (RealmAlreadyExists, ClientAlreadyExists):
        raise AdminError(409, 'conflict') from None
    except (RealmImportError, IntegrityError):
        db.session.rollback()
        repository = IdentityRepository(db.session)
        matches = repository.realms_with_normalized_name(value.name_normalized)
        if not update and matches:
            raise AdminError(409, 'conflict') from None
        if create_only_clients and matches:
            client = db.session.scalar(select(Client).where(
                Client.realm_id == matches[0].id,
                Client.client_id_normalized == value.clients[0].client_id_normalized))
            if client is not None:
                raise AdminError(409, 'conflict') from None
        raise AdminError(400, 'invalid_request') from None
    except RealmImportValidationError:
        raise AdminError(400, 'invalid_request') from None


def _realm(name: str) -> Realm:
    realm = IdentityRepository(db.session).get_realm(name)
    if realm is None:
        raise AdminError(404, 'not_found')
    return realm


def _client(realm: Realm, client_uuid: str) -> Client:
    client = db.session.scalar(select(Client).where(
        Client.id == client_uuid, Client.realm_id == realm.id))
    if client is None:
        raise AdminError(404, 'not_found')
    return client


def _flow(realm: Realm, alias: str) -> AuthenticationFlow:
    flow = db.session.scalar(select(AuthenticationFlow).where(
        AuthenticationFlow.realm_id == realm.id, AuthenticationFlow.alias == alias))
    if flow is None:
        raise AdminError(404, 'not_found')
    return flow


@admin.before_request
def authorize_admin():
    request.max_content_length = 2 * 1024 * 1024
    authorization = request.headers.get('Authorization', '')
    match = re.fullmatch(r'Bearer +([^\s,]+)', authorization, flags=re.IGNORECASE)
    if match is None:
        raise AdminError(401, 'unauthorized')
    master = IdentityRepository(db.session).get_realm('master')
    if master is None or not master.enabled:
        raise AdminError(401, 'unauthorized')
    try:
        claims = _token_service().verify(match[1], realm=master,
                                         audience='admin-cli', token_type='Bearer')
    except OAuthError:
        raise AdminError(401, 'unauthorized') from None
    user = IdentityRepository(db.session).get_user(master.id, claims['sub'])
    if user is None or 'admin' not in user.attributes.get('realmRoles', []):
        raise AdminError(403, 'forbidden')


@admin.errorhandler(AdminError)
def admin_error(error):
    db.session.rollback()
    response = jsonify(error=error.error)
    response.status_code = error.status_code
    if error.status_code == 401:
        response.headers['WWW-Authenticate'] = 'Bearer realm="master"'
    return response


@admin.errorhandler(HTTPException)
def admin_http_error(error):
    db.session.rollback()
    return jsonify(error='invalid_request' if error.code < 500 else 'server_error'), error.code


@admin.errorhandler(Exception)
def unexpected_admin_error(_error):
    db.session.rollback()
    log_failure('admin')
    return jsonify(error='server_error'), 500


@admin.route('/admin/realms', methods=['GET', 'POST'])
def realms():
    if request.method == 'GET':
        rows = db.session.scalars(select(Realm).order_by(Realm.name)).all()
        return jsonify([_realm_representation(row) for row in rows])
    value = _validated(_body(), update=False)
    realm = _import(value)
    response = jsonify(_realm_representation(realm))
    response.status_code = 201
    response.headers['Location'] = url_for('admin.realm_resource', realm=realm.name, _external=True)
    return response


@admin.route('/admin/realms/<realm>', methods=['GET', 'PUT', 'DELETE'])
def realm_resource(realm: str):
    row = _realm(realm)
    if request.method == 'GET':
        return jsonify(_realm_representation(row))
    if request.method == 'DELETE':
        if row.name == 'master':
            raise AdminError(400, 'invalid_request')
        delete_realm(db.session, row)
        db.session.commit()
        return '', 204
    document = _body()
    if 'realm' in document and document['realm'] != realm:
        raise AdminError(400, 'invalid_request')
    value = _validated({'realm': realm, **document}, update=True)
    _import(value, update=True)
    return '', 204


@admin.get('/admin/realms/<realm>/authentication/flows')
def authentication_flows(realm: str):
    row = _realm(realm)
    flows = db.session.scalars(select(AuthenticationFlow).where(
        AuthenticationFlow.realm_id == row.id).order_by(AuthenticationFlow.alias)).all()
    return jsonify([{
        'id': flow.id, 'alias': flow.alias, 'providerId': flow.provider_id,
        'builtIn': flow.built_in,
    } for flow in flows])


@admin.get('/admin/realms/<realm>/authentication/flows/<path:alias>/executions')
def authentication_flow_executions(realm: str, alias: str):
    row = _realm(realm)
    flow = _flow(row, alias)
    executions = AuthenticationFlowService(db.session).executions(flow.id)
    return jsonify([{
        'id': execution.id, 'providerId': execution.authenticator,
        'requirement': execution.requirement, 'priority': execution.priority,
    } for execution in executions])


@admin.post('/admin/realms/<realm>/authentication/flows/<path:alias>/copy')
def copy_authentication_flow(realm: str, alias: str):
    row = _realm(realm)
    source = _flow(row, alias)
    body = _body()
    name = body.get('newName')
    if (set(body) != {'newName'} or type(name) is not str
            or not name or name != name.strip() or len(name) > 255):
        raise AdminError(400, 'invalid_request')
    try:
        AuthenticationFlowService(db.session).copy_flow(row.id, source, name)
        db.session.commit()
    except ValueError:
        db.session.rollback()
        raise AdminError(409, 'conflict') from None
    except IntegrityError:
        db.session.rollback()
        raise AdminError(409, 'conflict') from None
    return '', 201


def _client_document(realm: Realm, body: dict, *, update: bool):
    return _validated({'realm': realm.name, 'clients': [body]}, update=update)


@admin.route('/admin/realms/<realm>/clients', methods=['GET', 'POST'])
def clients(realm: str):
    row = _realm(realm)
    if request.method == 'GET':
        if set(request.args) - {'clientId', 'first', 'max', 'search', 'viewableOnly', 'q'} or any(
                len(request.args.getlist(key)) != 1 for key in request.args):
            raise AdminError(400, 'invalid_request')
        if (request.args.get('search', 'false') not in {'true', 'false'}
                or request.args.get('viewableOnly', 'false') not in {'true', 'false'}):
            raise AdminError(400, 'invalid_request')
        try:
            first = int(request.args.get('first', '0'))
            maximum = int(request.args['max']) if 'max' in request.args else None
        except ValueError:
            raise AdminError(400, 'invalid_request') from None
        if first < 0 or maximum is not None and maximum < -1:
            raise AdminError(400, 'invalid_request')
        query = select(Client).where(Client.realm_id == row.id)
        if 'q' in request.args:
            try:
                fields = dict(token.split(':', 1) for token in shlex.split(request.args['q']))
                if any(not key for key in fields):
                    raise ValueError()
            except ValueError:
                raise AdminError(400, 'invalid_request') from None
            records = db.session.scalars(query.order_by(Client.client_id)).all()
            representations = [_client_representation(item) for item in records]
            matching = [item for item in representations if all(
                item['attributes'].get(key) == value for key, value in fields.items())]
            return jsonify(matching[first:] if maximum in (None, -1)
                           else matching[first:first + maximum])
        if request.args.get('clientId', '').strip():
            if request.args.get('search') == 'true':
                query = query.where(Client.client_id_normalized.contains(
                    request.args['clientId'].casefold(), autoescape=True))
            else:
                query = query.where(Client.client_id == request.args['clientId'])
        query = query.order_by(Client.client_id).offset(first)
        if maximum not in (None, -1):
            query = query.limit(maximum)
        records = db.session.scalars(query)
        return jsonify([_client_representation(item) for item in records])
    body = _body()
    value = _client_document(row, body, update=False)
    _import(value, update=True, create_only_clients=True)
    created = IdentityRepository(db.session).get_client(row.id, value.clients[0].client_id)
    response = jsonify(_client_representation(created))
    response.status_code = 201
    response.headers['Location'] = url_for('admin.client_resource', realm=realm,
                                           client_uuid=created.id, _external=True)
    return response


@admin.route('/admin/realms/<realm>/clients/<client_uuid>', methods=['GET', 'PUT', 'DELETE'])
def client_resource(realm: str, client_uuid: str):
    row = _realm(realm)
    client = _client(row, client_uuid)
    if request.method == 'GET':
        return jsonify(_client_representation(client))
    if request.method == 'DELETE':
        if row.name == 'master' and client.client_id == 'admin-cli':
            raise AdminError(400, 'invalid_request')
        delete_client(db.session, client)
        db.session.commit()
        return '', 204
    body = _body()
    if ('clientId' in body and body['clientId'] != client.client_id
            or 'id' in body and body['id'] != client_uuid):
        raise AdminError(400, 'invalid_request')
    body.pop('id', None)
    value = _client_document(row, {'clientId': client.client_id, **body}, update=True)
    _import(value, update=True)
    return '', 204


@admin.get('/admin/realms/<realm>/clients/<client_uuid>/session-count')
def client_session_count(realm: str, client_uuid: str):
    row = _realm(realm)
    client = _client(row, client_uuid)
    now = utc_now()
    count = db.session.scalar(select(func.count(UserSession.id)).where(
        UserSession.realm_id == row.id,
        or_(
            UserSession.client_id == client.id,
            select(AuthorizationCode.id).where(
                AuthorizationCode.user_session_id == UserSession.id,
                AuthorizationCode.client_id == client.id,
            ).exists(),
            select(RefreshToken.id).where(
                RefreshToken.user_session_id == UserSession.id,
                RefreshToken.client_id == client.id,
            ).exists(),
        ),
        UserSession.revoked_at.is_(None),
        UserSession.idle_expires_at > now,
        UserSession.max_expires_at > now,
    ))
    return jsonify(count=count or 0)
