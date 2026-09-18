import pytest
from sqlalchemy import func, select

from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationSession, Client
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.bootstrap import ensure_demo_realm
from tests.helpers import form_action, query_value


AUTH = "/realms/demo/protocol/openid-connect/auth"
BUNDLED_PARAMS = {
    "client_id": "demo-app",
    "redirect_uri": "http://localhost:9999/callback",
    "response_type": "code",
    "scope": "openid",
}


def test_bundled_client_authorization_page_accepts_omitted_pkce(app, client):
    response = client.get(AUTH, query_string=BUNDLED_PARAMS)

    assert response.status_code == 200
    action = form_action(response.text, "login-actions/authenticate")
    assert query_value(action, "client_id") == "demo-app"
    with app.app_context():
        authentication = db.session.get(
            AuthenticationSession, query_value(action, "tab_id")
        )
        assert authentication.scope == "openid"
        assert authentication.code_challenge is None
        assert authentication.code_challenge_method is None


def test_bootstrap_updates_existing_bundled_client_policy_only(app, client):
    with app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.get_realm("demo")
        bundled = repository.get_client(realm.id, "demo-app")
        bundled.pkce_policy = "S256"
        bundled_id = bundled.id
        repository.create_client(
            realm.id, "strict-app", redirect_uris=["https://example.test/callback"]
        )
        other_realm = repository.create_realm("other")
        repository.create_client(
            other_realm.id, "demo-app", redirect_uris=["https://example.test/callback"]
        )
        db.session.commit()

        for _ in range(2):
            ensure_demo_realm(db.session)
            db.session.commit()
            db.session.expire_all()
            assert repository.get_client(realm.id, "demo-app").id == bundled_id
            assert repository.get_client(realm.id, "demo-app").pkce_policy == "optional"
            assert repository.get_client(realm.id, "strict-app").pkce_policy == "S256"
            assert repository.get_client(other_realm.id, "demo-app").pkce_policy == "S256"
            assert db.session.scalar(select(func.count()).select_from(Client)) == 3

    assert client.get(AUTH, query_string=BUNDLED_PARAMS).status_code == 200


@pytest.mark.parametrize("optional", [False, True], ids=["default-strict", "optional"])
@pytest.mark.parametrize("pkce,valid_s256", [
    ({}, False),
    ({"code_challenge": "A" * 43, "code_challenge_method": "S256"}, True),
    ({"code_challenge": "A" * 43, "code_challenge_method": "plain"}, False),
    ({"code_challenge": "short", "code_challenge_method": "S256"}, False),
    ({"code_challenge": "!" * 43, "code_challenge_method": "S256"}, False),
    ({"code_challenge": "", "code_challenge_method": "S256"}, False),
    ({"code_challenge": "A" * 43}, False),
    ({"code_challenge_method": "S256"}, False),
])
def test_generic_client_policy_enforces_s256_when_supplied(
    app, client, optional, pkce, valid_s256
):
    with app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.get_realm("demo")
        policy = {"pkce_policy": "optional"} if optional else {}
        repository.create_client(
            realm.id,
            "generic-app",
            redirect_uris=["https://example.test/callback"],
            **policy,
        )
        db.session.commit()

    response = client.get(AUTH, query_string=BUNDLED_PARAMS | {
        "client_id": "generic-app",
        "redirect_uri": "https://example.test/callback",
    } | pkce)

    accepted = valid_s256 or (optional and not pkce)
    assert response.status_code == (200 if accepted else 302)
    if not accepted:
        assert query_value(response.location, 'error') == 'invalid_request'
    with app.app_context():
        assert db.session.scalar(
            select(func.count()).select_from(AuthenticationSession)
        ) == (1 if accepted else 0)
