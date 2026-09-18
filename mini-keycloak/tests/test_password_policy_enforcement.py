from datetime import timedelta

import pytest
from sqlalchemy import select

from mini_keycloak.extensions import db
from mini_keycloak.import_export.validation import validate_realm_import
from mini_keycloak.models import AuthenticationSession, Client, Credential, User
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.reset_credentials.flow import FlowStateError, ResetFlow
from mini_keycloak.services.realm_import import RealmImportService


def import_policy_realm(app, policy=None, *, update=False):
    importer = RealmImportService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET'])
    document = {
        'realm': 'password-policy',
        'clients': [{'clientId': 'browser',
                     'redirectUris': ['https://example.test/callback']}],
        'users': [{'username': 'alice', 'credentials': [
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


def permitted_session(realm):
    user = db.session.scalar(select(User).where(User.realm_id == realm.id))
    session = AuthenticationSession(tab_id='policy-test', realm_id=realm.id, realm=realm,
        client_id=db.session.scalar(select(Client.id).where(Client.realm_id == realm.id)),
        selected_user_id=user.id,
        current_execution='update-password', password_update_allowed=True,
        redirect_uri='https://example.test/callback', auth_notes={},
        expires_at=utc_now() + timedelta(minutes=5))
    db.session.add(session)
    db.session.commit()
    return session


def assert_policy_rejection_preserves_state(flow, session, password, monkeypatch):
    original_credential = db.session.execute(select(Credential.__table__)).one()
    original_session = db.session.execute(select(AuthenticationSession.__table__)).one()

    def forbidden_hash(_password):
        pytest.fail('Policy rejection must happen before hashing')

    with monkeypatch.context() as patch:
        patch.setattr(flow.store.passwords, 'hash', forbidden_hash)
        with pytest.raises(FlowStateError) as error:
            flow.update_password(session, password)
    assert str(error.value) == 'Password does not meet realm policy.'
    db.session.commit()
    assert db.session.execute(select(Credential.__table__)).one() == original_credential
    assert db.session.execute(select(AuthenticationSession.__table__)).one() == original_session
    assert session.password_update_allowed is True


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
        flow = ResetFlow(IdentityRepository(db.session))
        assert_policy_rejection_preserves_state(flow, session, weak, monkeypatch)
        flow.update_password(session, strong)
        db.session.commit()
        assert session.password_update_allowed is False
        assert IdentityRepository(db.session).password_matches(session.selected_user, strong)


@pytest.mark.parametrize('policy', [None, '', 'unknownPolicy(100)'])
def test_imported_policy_without_recognized_clauses_accepts_password(db_app, policy):
    with db_app.app_context():
        realm = import_policy_realm(db_app, policy)
        assert realm.password_policy == {'raw': policy or '', 'clauses': {}}
        session = permitted_session(realm)
        user = ResetFlow(IdentityRepository(db.session)).update_password(session, 'x')
        db.session.commit()
        assert session.password_update_allowed is False
        assert IdentityRepository(db.session).password_matches(user, 'x')


def test_empty_stored_policy_keeps_existing_password_contract(db_app):
    with db_app.app_context():
        realm = import_policy_realm(db_app)
        realm.password_policy = {}
        session = permitted_session(realm)
        user = ResetFlow(IdentityRepository(db.session)).update_password(session, 'x')
        db.session.commit()
        assert session.password_update_allowed is False
        assert IdentityRepository(db.session).password_matches(user, 'x')


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
        flow = ResetFlow(IdentityRepository(db.session))
        assert_policy_rejection_preserves_state(
            flow, session, 'Replacement-password-456!', monkeypatch)
