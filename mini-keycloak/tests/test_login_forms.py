import pytest

from mini_keycloak.authentication import AuthenticationProcessor, AuthenticatorRegistry
from mini_keycloak.authentication.forms import LoginFormsProvider
from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationExecution
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.reset_credentials.update_password import UPDATE_PASSWORD
from mini_keycloak.services.authentication_flows import AuthenticationFlowService
from tests.helpers import form_action, query_value


@pytest.fixture
def authentication_session(db_app):
    with db_app.app_context():
        identities = IdentityRepository(db.session)
        realm = identities.create_realm("forms-realm")
        client = identities.create_client(
            realm.id,
            "forms-client",
            redirect_uris=["https://client.example/callback"],
        )
        flow = AuthenticationFlowService(db.session).ensure_reset_flow(realm)
        executions = AuthenticationRepository(db.session).executions(flow.id)
        authentication_session = AuthenticationRepository(db.session).create_session(
            realm, client, client.redirect_uris[0], executions[0].id
        )
        authentication_session.flow_id = flow.id
        db.session.commit()
        yield authentication_session, executions


def forms(authentication_session, session_code="rotated-code"):
    return LoginFormsProvider(
        authentication_session.realm.name, authentication_session, session_code
    )


def test_reset_form_keeps_public_action_and_fields(db_app, authentication_session):
    authentication, executions = authentication_session
    execution_id = executions[0].id
    with db_app.test_request_context():
        html = forms(authentication).for_execution(
            execution_id
        ).create_password_reset(account=True)

    action = form_action(html, "login-actions/reset-credentials")
    assert query_value(action, "client_id") == "forms-client"
    assert query_value(action, "tab_id") == authentication.tab_id
    assert query_value(action, "execution") == execution_id
    assert query_value(action, "session_code") == "rotated-code"
    assert 'name="username"' in html
    assert 'name="tryAnotherWay"' in html


def test_update_password_form_keeps_public_action_and_fields(
    db_app, authentication_session
):
    authentication, _ = authentication_session
    with db_app.test_request_context():
        html = forms(authentication).for_execution(
            UPDATE_PASSWORD
        ).create_update_password("Try again.")

    action = form_action(html, "login-actions/required-action")
    assert query_value(action, "execution") == UPDATE_PASSWORD
    assert 'name="password-new"' in html
    assert 'name="password-confirm"' in html
    assert "Try again." in html


def test_login_form_keeps_authenticate_and_reset_actions(db_app, authentication_session):
    authentication, _ = authentication_session
    authentication.realm.forgot_password_allowed = True
    with db_app.test_request_context():
        html = forms(authentication).create_login("Continue signing in.")

    action = form_action(html, "login-actions/authenticate")
    assert query_value(action, "execution") == "login"
    assert query_value(action, "session_code") == "rotated-code"
    assert "login-actions/reset-credentials" in html
    assert "Continue signing in." in html


def test_form_provider_rejects_an_empty_execution_before_building_an_action(
    authentication_session,
):
    authentication, _ = authentication_session

    with pytest.raises(ValueError, match="Invalid authentication request"):
        forms(authentication).for_execution("")


def test_processor_rejects_unconfigured_execution_before_binding_forms(
    authentication_session,
):
    authentication, executions = authentication_session
    processor = AuthenticationProcessor(
        db.session,
        realm_name=authentication.realm.name,
        client_id=authentication.client.client_id,
        tab_id=authentication.tab_id,
        registry=AuthenticatorRegistry({}),
        forms=forms(authentication),
    )
    unknown = AuthenticationExecution(
        id="unknown-execution",
        flow_id=authentication.flow_id,
        authenticator="unknown",
        requirement="REQUIRED",
        priority=100,
    )

    with pytest.raises(ValueError, match="Invalid authentication request"):
        processor.create_authenticator_context(
            unknown, object(), executions, forms(authentication)
        )


def test_processor_binds_forms_to_the_validated_current_execution(
    authentication_session,
):
    authentication, executions = authentication_session
    processor = AuthenticationProcessor(
        db.session,
        realm_name=authentication.realm.name,
        client_id=authentication.client.client_id,
        tab_id=authentication.tab_id,
        registry=AuthenticatorRegistry({}),
        forms=forms(authentication),
    )

    context = processor.create_authenticator_context(
        executions[0], object(), executions
    )

    assert context.form.execution_id == executions[0].id
