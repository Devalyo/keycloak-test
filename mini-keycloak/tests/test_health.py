import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import event, select

from mini_keycloak.app import create_app
from mini_keycloak.extensions import db
from mini_keycloak.models import Realm, RealmKey
from mini_keycloak.security.key_encryption import encrypt_private_pem
from mini_keycloak.services.keys import RealmKeyService


def test_liveness_does_not_connect_to_database(tmp_path):
    app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI':
                      f'sqlite:///{tmp_path}/missing-directory/database.sqlite'})
    response = app.test_client().get('/health/live')
    assert (response.status_code, response.json) == (200, {'status': 'ok'})


def test_readiness_requires_reachable_database_and_schema(tmp_path, caplog):
    for url in [f'sqlite:///{tmp_path}/missing-directory/database.sqlite', 'sqlite:///:memory:']:
        app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': url})
        caplog.clear()
        response = app.test_client().get('/health/ready')
        assert (response.status_code, response.json) == (503, {'status': 'unavailable'})
        assert url not in response.text + caplog.text
    assert caplog.records
    for record in caplog.records:
        assert record.getMessage() == 'Health readiness check failed'
        assert record.request_id == response.headers['X-Request-ID']
        assert record.exc_info is None and record.exc_text is None and record.stack_info is None


def test_readiness_without_enabled_realms_is_ready(db_app):
    response = db_app.test_client().get('/health/ready')
    assert (response.status_code, response.json) == (200, {'status': 'ok'})


def test_readiness_with_valid_keys_is_read_only_and_releases_session(app, client):
    statements = []
    with app.app_context():
        engine = db.engine
        original = db.session.scalar(select(RealmKey.encrypted_private_pem))
        db.session.rollback()

        def capture(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(engine, 'before_cursor_execute', capture)
        try:
            response = client.get('/health/ready')
        finally:
            event.remove(engine, 'before_cursor_execute', capture)
        assert (response.status_code, response.json) == (200, {'status': 'ok'})
        assert statements and all(statement.lstrip().upper().startswith('SELECT') for statement in statements)
        assert not db.session.registry.has()
        assert db.session.scalar(select(RealmKey.encrypted_private_pem)) == original


@pytest.mark.parametrize('damage', ['missing', 'duplicate', 'algorithm', 'ciphertext', 'pem', 'non-rsa', 'secret'])
def test_readiness_fails_closed_for_unusable_active_keys(app, client, caplog, damage):
    with app.app_context():
        key = db.session.scalar(select(RealmKey))
        if damage == 'missing':
            key.active = False
        elif damage == 'duplicate':
            # Model schema intentionally allows multiple active rows; readiness must detect them.
            db.session.add(RealmKey(realm_id=key.realm_id, kid='duplicate-private-sentinel',
                encrypted_private_pem=key.encrypted_private_pem, public_jwk=key.public_jwk))
        elif damage == 'algorithm':
            key.algorithm = 'ES256'
        elif damage == 'ciphertext':
            key.encrypted_private_pem = 'ciphertext-private-sentinel'
        elif damage in {'pem', 'non-rsa'}:
            pem = b'pem-private-sentinel'
            if damage == 'non-rsa':
                pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption())
            key.encrypted_private_pem = encrypt_private_pem(pem, app.config['OIDC_KEY_ENCRYPTION_SECRET'])
        elif damage == 'secret':
            app.config['OIDC_KEY_ENCRYPTION_SECRET'] = 'wrong-secret-private-sentinel'
        db.session.commit()
        response = client.get('/health/ready')
        assert (response.status_code, response.json) == (503, {'status': 'unavailable'})
        assert not db.session.registry.has()
    assert 'private-sentinel' not in response.text + caplog.text
    assert caplog.records and all(record.exc_info is None for record in caplog.records)


def test_readiness_checks_every_enabled_realm_and_ignores_retained_keys(app, client):
    with app.app_context():
        realm = Realm(name='second-private-sentinel')
        db.session.add(realm)
        db.session.commit()
        assert client.get('/health/ready').status_code == 503
        realm = db.session.scalar(select(Realm).where(Realm.name == 'second-private-sentinel'))
        RealmKeyService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET']).ensure_active_key(realm.id)
        db.session.add(RealmKey(realm_id=realm.id, kid='retained', active=False,
            encrypted_private_pem='invalid-retained-key', public_jwk={}))
        db.session.commit()
        assert client.get('/health/ready').status_code == 200
        realm = db.session.scalar(select(Realm).where(Realm.name == 'second-private-sentinel'))
        realm.enabled = False
        for key in db.session.scalars(select(RealmKey).where(RealmKey.realm_id == realm.id)):
            key.encrypted_private_pem = 'invalid-disabled-key'
        db.session.commit()
        assert client.get('/health/ready').status_code == 200


def test_readiness_rolls_back_pending_request_changes_without_autoflush(app, client):
    with app.app_context():
        realm = db.session.scalar(select(Realm))
        original = realm.display_name
        realm.display_name = 'must-not-persist'
        response = client.get('/health/ready')
        assert response.status_code == 200
        assert db.session.scalar(select(Realm.display_name)) == original


@pytest.mark.parametrize('damage', [
    'missing', 'not-object', 'null', 'kid', 'kty', 'alg', 'use', 'n', 'e',
    'numeric-n', 'numeric-e', 'malformed-n', 'malformed-e', 'padded-n',
    'leading-zero-n', 'missing-n', 'missing-e', 'swapped', 'private-member',
])
def test_readiness_validates_the_public_private_key_pair_read_only(app, client, caplog, damage):
    import base64

    with app.app_context():
        key = db.session.scalar(select(RealmKey))
        public = dict(key.public_jwk)
        private_material = key.encrypted_private_pem
        if damage == 'missing':
            public = {}
        elif damage == 'not-object':
            public = ['private-sentinel']
        elif damage == 'null':
            public = None
        elif damage in {'kid', 'kty', 'alg', 'use'}:
            public[damage] = 'private-sentinel'
        elif damage in {'n', 'e'}:
            public[damage] = 'Aw'  # A well-encoded but mismatched integer.
        elif damage.startswith('numeric-'):
            public[damage[-1]] = 65537
        elif damage.startswith('malformed-'):
            public[damage[-1]] = 'private-sentinel!'
        elif damage == 'padded-n':
            public['n'] += '=='
        elif damage == 'leading-zero-n':
            modulus = base64.urlsafe_b64decode(public['n'] + '==')
            public['n'] = base64.urlsafe_b64encode(b'\0' + modulus).rstrip(b'=').decode()
        elif damage.startswith('missing-'):
            public.pop(damage[-1])
        elif damage == 'swapped':
            other = Realm(name='other-private-sentinel')
            db.session.add(other)
            db.session.flush()
            other_key = RealmKeyService(db.session, app.config['OIDC_KEY_ENCRYPTION_SECRET']).ensure_active_key(other.id)
            public = dict(other_key.public_jwk, kid=key.kid)
        elif damage == 'private-member':
            public['d'] = 'private-sentinel'
        key.public_jwk = public
        db.session.commit()
        statements = []
        engine = db.engine

        def capture(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(engine, 'before_cursor_execute', capture)
        try:
            response = client.get('/health/ready')
        finally:
            event.remove(engine, 'before_cursor_execute', capture)
        assert (response.status_code, response.json) == (503, {'status': 'unavailable'})
        assert statements and all(statement.lstrip().upper().startswith('SELECT') for statement in statements)
        assert not db.session.registry.has()
    assert 'private-sentinel' not in response.text + caplog.text
    assert private_material not in response.text + caplog.text
    assert caplog.records
    for record in caplog.records:
        assert record.getMessage() == 'Health readiness check failed'
        assert record.request_id == response.headers['X-Request-ID']
        assert record.exc_info is None and record.exc_text is None and record.stack_info is None
