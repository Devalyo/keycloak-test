from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select

from mini_keycloak.authentication import (
    AuthenticationProcessor, AuthenticatorContext, AuthenticatorRegistry, FlowStatus,
)
from mini_keycloak.authentication.constants import (
    AUTHENTICATION_FLOW_COMPLETED, CURRENT_AUTHENTICATION_EXECUTION,
    RESET_CREDENTIALS_CHOOSE_USER, RESET_CREDENTIAL_EMAIL, RESET_PASSWORD,
)
from mini_keycloak.extensions import db
from mini_keycloak.import_export.validation import validate_realm_import
from mini_keycloak.models import AuthenticationSession, Client, Credential, ResetEmail, User
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.reset_credentials.authenticators import (
    ACTION_TOKEN_USER_ID, ResetCredentialChooseUser, ResetCredentialEmail, ResetPassword,
)
from mini_keycloak.security.passwords import PasswordService
from mini_keycloak.services.action_tokens import ResetActionTokenService
from mini_keycloak.services.authentication_flows import AuthenticationFlowService
from mini_keycloak.services.realm_import import RealmImportService
from tests.helpers import form_action, query_value


def import_policy_realm(app, policy=None, *, update=False):
    importer = RealmImportService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET'])
    document = {
        'realm': 'password-policy',
        'clients': [{'clientId': 'browser',
                     'redirectUris': ['https://example.test/callback']}],
        'users': [{'username': 'alice', 'email': 'alice@example.test', 'credentials': [
            {'type': 'password', 'value': 'Original-password-123!'}]}],
    }
    if policy is not None and not update:
        document['passwordPolicy'] = policy
    realm = importer.import_realm(validate_realm_import(document).value)
    db.session.commit()
    if update:
        document = {'realm': realm.name, 'passwordPolicy': policy}
        realm = importer.import_realm(
            validate_realm_import(document, update=True).value, update=True)
        db.session.commit()
    return realm


def processor(session):
    return AuthenticationProcessor(db.session, realm_name=session.realm.name,
        client_id=session.client.client_id, tab_id=session.tab_id,
        registry=AuthenticatorRegistry({
            RESET_CREDENTIALS_CHOOSE_USER: ResetCredentialChooseUser(),
            RESET_CREDENTIAL_EMAIL: ResetCredentialEmail(), RESET_PASSWORD: ResetPassword(),
        }))


def permitted_session(realm):
    user = db.session.scalar(select(User).where(User.realm_id == realm.id))
    flow = AuthenticationFlowService(db.session).ensure_reset_flow(realm)
    executions = {item.authenticator: item.id for item in
                  AuthenticationFlowService(db.session).executions(flow.id)}
    session = AuthenticationSession(tab_id='policy-test', realm_id=realm.id, realm=realm,
        client_id=db.session.scalar(select(Client.id).where(Client.realm_id == realm.id)),
        flow_id=flow.id, current_execution=executions[RESET_CREDENTIALS_CHOOSE_USER],
        redirect_uri='https://example.test/callback', auth_notes={},
        expires_at=utc_now() + timedelta(minutes=5))
    db.session.add(session)
    db.session.flush()
    flow_processor = processor(session)
    assert flow_processor.process_flow().page == 'account'
    assert flow_processor.process_action(executions[RESET_CREDENTIALS_CHOOSE_USER],
                                         {'username': user.username}).page == 'login'
    message = db.session.scalar(select(ResetEmail))
    continued, selected = ResetActionTokenService(db.session).consume(realm.name, message.action_token)
    assert continued is session and selected.id == user.id
    session.auth_notes[ACTION_TOKEN_USER_ID] = selected.id
    outcome = flow_processor.process_flow()
    assert outcome.page == 'password' and outcome.execution_id == executions[RESET_PASSWORD]
    db.session.commit()
    return session


def assert_policy_rejection_preserves_state(session, password, monkeypatch):
    original_credential = db.session.execute(select(Credential.__table__)).one()
    original_session = db.session.execute(select(AuthenticationSession.__table__)).one()

    def forbidden_hash(self, _password):
        pytest.fail('Policy rejection must happen before hashing')

    execution = next(item for item in AuthenticationFlowService(db.session).executions(session.flow_id)
                     if item.authenticator == RESET_PASSWORD)
    context = AuthenticatorContext(AuthenticationRepository(db.session), session,
                                   session.realm, session.client, execution)
    with monkeypatch.context() as patch:
        patch.setattr(PasswordService, 'hash', forbidden_hash)
        result = ResetPassword().action(context, {
            'password-new': password, 'password-confirm': password})
    assert result.status == FlowStatus.CHALLENGE and result.page == 'password'
    assert result.message == 'Passwords must match and meet realm policy.'
    db.session.commit()
    assert db.session.execute(select(Credential.__table__)).one() == original_credential
    assert db.session.execute(select(AuthenticationSession.__table__)).one() == original_session
    assert session.auth_notes[ACTION_TOKEN_USER_ID] == session.selected_user_id
    assert session.auth_notes[CURRENT_AUTHENTICATION_EXECUTION] == execution.id
    assert AUTHENTICATION_FLOW_COMPLETED not in session.auth_notes


def update_password(session, password):
    execution = next(item for item in AuthenticationFlowService(db.session).executions(session.flow_id)
                     if item.authenticator == RESET_PASSWORD)
    assert processor(session).process_action(execution.id, {
        'password-new': password, 'password-confirm': password}).complete
    db.session.commit()
    assert ACTION_TOKEN_USER_ID not in session.auth_notes
    assert session.auth_notes[AUTHENTICATION_FLOW_COMPLETED] == 'true'
    assert session.execution_status[execution.id] == 'SUCCESS'


def test_password_continuation_preserves_required_action_form_contract(db_app):
    with db_app.app_context():
        realm = import_policy_realm(db_app)
        session = permitted_session(realm)
        tab_id = session.tab_id
        execution_id = next(item.id for item in
            AuthenticationFlowService(db.session).executions(session.flow_id)
            if item.authenticator == RESET_PASSWORD)
    response = db_app.test_client().get(
        '/realms/password-policy/login-actions/reset-credentials',
        query_string={'client_id': 'browser', 'tab_id': tab_id})
    assert response.status_code == 200
    action = form_action(response.text, '/realms/password-policy/login-actions/required-action')
    assert urlsplit(action).path == '/realms/password-policy/login-actions/required-action'
    assert set(parse_qs(urlsplit(action).query)) == {'client_id', 'tab_id', 'execution'}
    assert query_value(action, 'client_id') == 'browser'
    assert query_value(action, 'tab_id') == tab_id
    assert query_value(action, 'execution') == execution_id
    assert 'name="password-new"' in response.text
    assert 'name="password-confirm"' in response.text


@pytest.mark.parametrize('policy,clauses,weak,strong', [
    ('length(8)', {'length': 8}, 'short', 'abcdefgh'),
    ('digits(2)', {'digits': 2}, 'one1', 'two١٢'),
    ('upperCase(1)', {'upperCase': 1}, 'lower', 'É'),
    ('lowerCase(1)', {'lowerCase': 1}, 'UPPER', 'é'),
    ('specialChars(1)', {'specialChars': 1}, 'plain١', 'plain!'),
    ('length(5) and digits(1) and upperCase(1) and lowerCase(1) and specialChars(1)',
     {'length': 5, 'digits': 1, 'upperCase': 1, 'lowerCase': 1, 'specialChars': 1},
     'Éé١!', 'Éé١!界'),
])
@pytest.mark.parametrize('update', [False, True])
def test_imported_policy_rejection_preserves_password_and_permission_for_retry(
        db_app, monkeypatch, policy, clauses, weak, strong, update):
    with db_app.app_context():
        realm = import_policy_realm(db_app, policy, update=update)
        assert realm.password_policy == {'raw': policy, 'clauses': clauses}
        session = permitted_session(realm)
        assert_policy_rejection_preserves_state(session, weak, monkeypatch)
        update_password(session, strong)
        assert session.password_update_allowed is False
        assert IdentityRepository(db.session).password_matches(session.selected_user, strong)


@pytest.mark.parametrize('policy', [None, '', 'unknownPolicy(100)'])
def test_imported_policy_without_recognized_clauses_accepts_password(db_app, policy):
    with db_app.app_context():
        realm = import_policy_realm(db_app, policy)
        assert realm.password_policy == {'raw': policy or '', 'clauses': {}}
        session = permitted_session(realm)
        update_password(session, 'x')
        assert session.password_update_allowed is False
        assert IdentityRepository(db.session).password_matches(session.selected_user, 'x')


def test_empty_stored_policy_keeps_existing_password_contract(db_app):
    with db_app.app_context():
        realm = import_policy_realm(db_app)
        realm.password_policy = {}
        session = permitted_session(realm)
        update_password(session, 'x')
        assert session.password_update_allowed is False
        assert IdentityRepository(db.session).password_matches(session.selected_user, 'x')


@pytest.mark.parametrize('policy', [
    None, [], 'length(8)', 8,
    {'raw': 'length(8)', 'clauses': None},
    {'raw': 'length(8)', 'clauses': []},
    {'raw': 'length(8)', 'clauses': 'length(8)'},
    {'raw': 'length(8)', 'clauses': 8},
    {'raw': 'length(8)', 'clauses': {'length': None}},
    {'raw': 'length(8)', 'clauses': {'length': '8'}},
    {'raw': 'length(8)', 'clauses': {'length': []}},
    {'raw': 'length(8)', 'clauses': {'length': {}}},
    {'raw': 'length(8)', 'clauses': {'length': True}},
    {'raw': 'length(8)', 'clauses': {'length': -1}},
])
def test_malformed_stored_policy_rejects_before_hash_or_state_mutation(
        db_app, monkeypatch, policy):
    with db_app.app_context():
        realm = import_policy_realm(db_app, 'length(8)')
        realm.password_policy = policy
        session = permitted_session(realm)
        assert_policy_rejection_preserves_state(
            session, 'Replacement-password-456!', monkeypatch)
