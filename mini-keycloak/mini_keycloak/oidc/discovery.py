from flask import abort, current_app, jsonify

from mini_keycloak.extensions import db
from mini_keycloak.oidc import oidc
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.repositories.keys import RealmKeyRepository
from mini_keycloak.services.keys import RealmKeyService
from mini_keycloak.services.tokens import realm_issuer


def _available_realm(realm_name: str):
    realm = IdentityRepository(db.session).get_realm(realm_name)
    if realm is None or not realm.enabled:
        abort(404)
    if RealmKeyRepository(db.session).get_active(realm.id) is None:
        response = jsonify(error="temporarily_unavailable")
        response.status_code = 503
        abort(response)
    return realm


def implemented_capabilities() -> dict:
    """Expand alongside the protocol tasks that implement each capability."""
    return {
        "grant_types_supported": ["authorization_code", "password", "refresh_token"],
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@oidc.get("/realms/<realm>/.well-known/openid-configuration")
def openid_configuration(realm: str):
    enabled_realm = _available_realm(realm)
    issuer = realm_issuer(enabled_realm, current_app.config['EXTERNAL_URL'])
    endpoint_base = issuer + "/protocol/openid-connect"
    return jsonify(
        issuer=issuer,
        authorization_endpoint=endpoint_base + "/auth",
        token_endpoint=endpoint_base + "/token",
        userinfo_endpoint=endpoint_base + "/userinfo",
        end_session_endpoint=endpoint_base + "/logout",
        jwks_uri=endpoint_base + "/certs",
        **implemented_capabilities(),
    )


@oidc.get("/realms/<realm>/protocol/openid-connect/certs")
def certs(realm: str):
    enabled_realm = _available_realm(realm)
    service = RealmKeyService(db.session, current_app.config["OIDC_KEY_ENCRYPTION_SECRET"])
    return jsonify(service.public_jwks(enabled_realm.id))
