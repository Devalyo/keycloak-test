from flask import jsonify, request

from mini_keycloak.extensions import db
from mini_keycloak.oidc import oidc
from mini_keycloak.oidc.errors import OAuthError
from mini_keycloak.oidc.token import _token_service
from mini_keycloak.repositories.identity import IdentityRepository


@oidc.route('/realms/<realm>/protocol/openid-connect/userinfo', methods=['GET', 'POST'])
def userinfo(realm: str):
    enabled_realm = IdentityRepository(db.session).get_realm(realm)
    if enabled_realm is None or not enabled_realm.enabled:
        response = jsonify(error='invalid_request')
        response.status_code = 404
    else:
        try:
            service = _token_service()
            raw = service.bearer_token(authorization=request.headers.get('Authorization'),
                form=request.form, query=request.args, method=request.method, content_type=request.mimetype)
            response = jsonify(service.userinfo(raw, realm=enabled_realm))
        except OAuthError as error:
            response = jsonify(error=error.error)
            response.status_code = error.status_code
            response.headers['WWW-Authenticate'] = f'Bearer error="{error.error}"'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response
