import pytest
from flask import current_app

from mini_keycloak.extensions import db
from mini_keycloak.flow import CHOOSE_USER_EXECUTION
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.bootstrap import ensure_demo_realm
from mini_keycloak.services.keys import RealmKeyService
from tests.helpers import form_action, query_value


def _create_dynamic_identity(repository, realm_name="configured"):
    realm = repository.create_realm(realm_name)
    realm.password_grant_enabled = True
    RealmKeyService(db.session, current_app.config['OIDC_KEY_ENCRYPTION_SECRET']).ensure_active_key(realm.id)
    client = repository.create_client(
        realm.id,
        "configured-app",
        redirect_uris=["https://configured.example.test/callback"],
        direct_access_grants_enabled=True,
    )
    repository.create_user(
        realm.id,
        "configured-user",
        "configured-user@example.test",
        "ConfiguredPassw0rd!",
    )
    return realm, client


def test_authorization_resolves_realm_client_and_exact_redirect(db_app):
    with db_app.app_context():
        ensure_demo_realm(db.session)
        db.session.commit()
    client = db_app.test_client()
    good = client.get(
        "/realms/demo/protocol/openid-connect/auth",
        query_string={
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:9999/callback",
            "response_type": "code",
            "scope": "openid",
            "code_challenge": "A" * 43,
            "code_challenge_method": "S256",
        },
    )
    attacker = client.get(
        "/realms/demo/protocol/openid-connect/auth",
        query_string={
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:9999/callback/attacker",
            "response_type": "code",
            "scope": "openid",
            "code_challenge": "A" * 43,
            "code_challenge_method": "S256",
        },
    )
    assert good.status_code == 200
    assert attacker.status_code == 400


def test_same_client_id_in_another_realm_cannot_access_poc_user(db_app):
    with db_app.app_context():
        ensure_demo_realm(db.session)
        repository = IdentityRepository(db.session)
        other = repository.create_realm("other")
        other.password_grant_enabled = True
        repository.create_client(
            other.id,
            "demo-app",
            redirect_uris=["http://localhost:9999/callback"],
            direct_access_grants_enabled=True,
        )
        db.session.commit()
    response = db_app.test_client().post(
        "/realms/other/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "demo-app",
            "username": "demo-user",
            "password": "DemoPassw0rd!",
        },
    )
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_grant"}


def test_password_grant_rejects_unauthenticated_confidential_client(db_app):
    with db_app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.create_realm("confidential")
        repository.create_client(
            realm.id,
            "service-app",
            redirect_uris=["https://service.example.test/callback"],
            public_client=False,
            direct_access_grants_enabled=True,
        )
        repository.create_user(
            realm.id,
            "service-user",
            "service-user@example.test",
            "ValidPassw0rd!",
        )
        db.session.commit()

    response = db_app.test_client().post(
        "/realms/confidential/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "service-app",
            "username": "service-user",
            "password": "ValidPassw0rd!",
        },
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_client"}


def test_separately_configured_realm_supports_authorization_and_password_grant(db_app):
    with db_app.app_context():
        _create_dynamic_identity(IdentityRepository(db.session))
        db.session.commit()

    client = db_app.test_client()
    authorization = client.get(
        "/realms/configured/protocol/openid-connect/auth",
        query_string={
            "client_id": "configured-app",
            "redirect_uri": "https://configured.example.test/callback",
            "response_type": "code",
            "scope": "openid",
            "code_challenge": "A" * 43,
            "code_challenge_method": "S256",
        },
    )
    token = client.post(
        "/realms/configured/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "configured-app",
            "username": "configured-user",
            "password": "ConfiguredPassw0rd!",
        },
    )

    assert authorization.status_code == 200
    assert token.status_code == 200
    assert token.get_json()["access_token"]


@pytest.mark.parametrize(
    ("disabled_policy", "expected_status"),
    [("realm", 404), ("client", 400)],
    ids=["disabled-realm", "disabled-client"],
)
def test_authorization_rejects_disabled_realm_or_client(
    db_app, disabled_policy, expected_status
):
    with db_app.app_context():
        realm, client = _create_dynamic_identity(IdentityRepository(db.session))
        if disabled_policy == "realm":
            realm.enabled = False
        else:
            client.enabled = False
        db.session.commit()

    response = db_app.test_client().get(
        "/realms/configured/protocol/openid-connect/auth",
        query_string={
            "client_id": "configured-app",
            "redirect_uri": "https://configured.example.test/callback",
            "response_type": "code",
        },
    )

    assert response.status_code == expected_status


@pytest.mark.parametrize(
    "disabled_policy",
    ["realm", "client", "direct-grant"],
    ids=["disabled-realm", "disabled-client", "disabled-direct-grant"],
)
def test_password_grant_rejects_disabled_realm_client_or_direct_grant(
    db_app, disabled_policy
):
    with db_app.app_context():
        realm, client = _create_dynamic_identity(IdentityRepository(db.session))
        if disabled_policy == "realm":
            realm.enabled = False
        elif disabled_policy == "client":
            client.enabled = False
        else:
            client.direct_access_grants_enabled = False
        db.session.commit()

    response = db_app.test_client().post(
        "/realms/configured/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "configured-app",
            "username": "configured-user",
            "password": "ConfiguredPassw0rd!",
        },
    )

    expected_status, expected_error = {
        'realm': (404, 'invalid_request'),
        'client': (401, 'invalid_client'),
        'direct-grant': (400, 'unauthorized_client'),
    }[disabled_policy]
    assert response.status_code == expected_status
    assert response.get_json() == {"error": expected_error}


def test_debug_outbox_is_not_an_http_endpoint(db_app):
    assert db_app.test_client().get("/debug/outbox").status_code == 404


def test_disabled_client_rejects_existing_session_without_selector_mutation(db_app):
    with db_app.app_context():
        ensure_demo_realm(db.session)
        db.session.commit()

    client = db_app.test_client()
    authorization = client.get(
        "/realms/demo/protocol/openid-connect/auth",
        query_string={
            "client_id": "demo-app",
            "redirect_uri": "http://localhost:9999/callback",
            "response_type": "code",
            "scope": "openid",
        },
    )
    tab_id = query_value(
        form_action(authorization.text, "login-actions/authenticate"), "tab_id"
    )
    reset = client.get(
        "/realms/demo/login-actions/reset-credentials",
        query_string={"client_id": "demo-app", "tab_id": tab_id},
    )
    selector_action = form_action(reset.text, "login-actions/reset-credentials")

    with db_app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.get_realm("demo")
        assert realm is not None
        persistent_client = repository.get_client(realm.id, "demo-app")
        assert persistent_client is not None
        persistent_client.enabled = False
        db.session.commit()

    rejected = client.post(selector_action, data={"tryAnotherWay": ""})
    assert rejected.status_code == 400

    with db_app.app_context():
        session = db_app.extensions["mini_keycloak_store"].get_auth_session(tab_id)
        assert session is not None
        assert session.current_execution == CHOOSE_USER_EXECUTION
        assert session.auth_notes == {}
