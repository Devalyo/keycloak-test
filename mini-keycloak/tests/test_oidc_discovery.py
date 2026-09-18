import pytest
from sqlalchemy import select

from mini_keycloak.extensions import db
from mini_keycloak.models import RealmKey
from mini_keycloak.repositories.identity import IdentityRepository


DISCOVERY = "/realms/demo/.well-known/openid-configuration"
CERTS = "/realms/demo/protocol/openid-connect/certs"


def test_discovery_uses_configured_external_origin_and_prefix(app, client):
    app.config["EXTERNAL_URL"] = "https://identity.example.test/auth/"
    response = client.get(DISCOVERY, headers={"Host": "localhost", "X-Forwarded-Host": "forwarded.test"})
    assert response.status_code == 200
    metadata = response.get_json()
    issuer = "https://identity.example.test/auth/realms/demo"
    assert metadata["issuer"] == issuer
    assert metadata["authorization_endpoint"] == issuer + "/protocol/openid-connect/auth"
    assert metadata["token_endpoint"] == issuer + "/protocol/openid-connect/token"
    assert metadata["jwks_uri"] == issuer + "/protocol/openid-connect/certs"
    assert "untrusted.test" not in response.get_data(as_text=True)
    assert "forwarded.test" not in response.get_data(as_text=True)


def test_discovery_only_advertises_currently_implemented_capabilities(client):
    response = client.get(DISCOVERY)
    assert response.status_code == 200
    metadata = response.get_json()
    assert metadata["grant_types_supported"] == ["authorization_code", "password", "refresh_token"]
    assert metadata["response_types_supported"] == ["code"]
    assert metadata["subject_types_supported"] == ["public"]
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert metadata["token_endpoint_auth_methods_supported"] == ["none", "client_secret_basic", "client_secret_post"]
    assert metadata["id_token_signing_alg_values_supported"] == ["RS256"]
    assert metadata['userinfo_endpoint'] == metadata['issuer'] + '/protocol/openid-connect/userinfo'
    assert metadata['end_session_endpoint'] == metadata['issuer'] + '/protocol/openid-connect/logout'
    assert 'revocation_endpoint' not in metadata


def test_jwks_contains_only_realm_public_keys_including_retained_keys(app, client):
    from mini_keycloak.services.keys import RealmKeyService

    with app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.get_realm("demo")
        original = db.session.scalar(select(RealmKey).where(RealmKey.realm_id == realm.id))
        original.active = False
        # Even an accidentally contaminated stored JWK must not leak private members.
        original.public_jwk = {**original.public_jwk, "d": "private-sentinel", "p": "prime-sentinel"}
        service = RealmKeyService(db.session, app.config["OIDC_KEY_ENCRYPTION_SECRET"])
        active = service.ensure_active_key(realm.id)
        other = repository.create_realm("other")
        other_key = service.ensure_active_key(other.id)
        expected_kids = {original.kid, active.kid}
        other_kid = other_key.kid
        db.session.commit()
    response = client.get(CERTS)
    assert response.status_code == 200
    keys = response.get_json()["keys"]
    assert {key["kid"] for key in keys} == expected_kids
    assert other_kid not in {key["kid"] for key in keys}
    for key in keys:
        assert set(key) == {"kid", "kty", "alg", "use", "n", "e"}
        assert (key["kty"], key["alg"], key["use"]) == ("RSA", "RS256", "sig")
    assert "sentinel" not in response.get_data(as_text=True)
    assert "PRIVATE" not in response.get_data(as_text=True)


@pytest.mark.parametrize("path", [DISCOVERY, CERTS])
@pytest.mark.parametrize("realm_state", ["missing", "disabled"])
def test_metadata_hides_missing_and_disabled_realms(app, client, path, realm_state):
    if realm_state == "missing":
        path = path.replace("/demo/", "/missing/")
    else:
        with app.app_context():
            realm = IdentityRepository(db.session).get_realm("demo")
            realm.enabled = False
            db.session.commit()
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("path", [DISCOVERY, CERTS])
def test_enabled_realm_without_active_key_fails_closed(app, client, path):
    with app.app_context():
        for key in db.session.scalars(select(RealmKey)):
            key.active = False
        db.session.commit()
    response = client.get(path)
    assert response.status_code == 503
    assert response.get_json() == {"error": "temporarily_unavailable"}
    with app.app_context():
        assert not db.session.scalars(select(RealmKey).where(RealmKey.active.is_(True))).all()
