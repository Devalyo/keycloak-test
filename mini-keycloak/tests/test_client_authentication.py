import base64
from urllib.parse import quote_plus

import pytest
from sqlalchemy import select
from werkzeug.datastructures import MultiDict

from mini_keycloak.extensions import db
from mini_keycloak.models import Client


TOKEN = '/realms/demo/protocol/openid-connect/token'
SECRET = 'a secret:+%雪'


def basic(client_id='demo-app', secret=SECRET):
    credentials = f'{quote_plus(client_id)}:{quote_plus(secret)}'.encode()
    return {'Authorization': 'Basic ' + base64.b64encode(credentials).decode()}


def confidential(app):
    from mini_keycloak.services.clients import ClientService
    with app.app_context():
        client = db.session.scalar(select(Client))
        client.public_client = False
        ClientService(db.session).set_secret(client, SECRET)
        db.session.commit()


def test_client_secret_is_argon2_hashed_and_verified(app):
    from mini_keycloak.security.client_secrets import ClientSecretService
    confidential(app)
    with app.app_context():
        stored = db.session.scalar(select(Client)).secret_hash
        assert stored.startswith('$argon2id$')
        assert SECRET not in stored
        secrets = ClientSecretService()
        assert secrets.verify(stored, SECRET)
        assert not secrets.verify(stored, 'wrong')
        assert not secrets.verify('broken hash', SECRET)


def test_public_client_authenticates_by_id_before_grant_validation(client):
    response = client.post(TOKEN, data={'client_id': 'demo-app', 'grant_type': 'unknown'})
    assert response.status_code == 400
    assert response.json == {'error': 'unsupported_grant_type'}


@pytest.mark.parametrize('method', ['basic', 'post'])
def test_confidential_client_accepts_one_authentication_method(app, client, method):
    confidential(app)
    form = {'grant_type': 'unknown'}
    headers = basic() if method == 'basic' else {}
    if method == 'post':
        form.update(client_id='demo-app', client_secret=SECRET)
    response = client.post(TOKEN, data=form, headers=headers)
    assert response.status_code == 400
    assert response.json == {'error': 'unsupported_grant_type'}


@pytest.mark.parametrize('form,headers', [
    ({'client_id': 'demo-app'}, {}),
    ({'client_id': 'demo-app', 'client_secret': 'wrong'}, {}),
    ({}, basic(secret='wrong')),
    ({}, {'Authorization': 'Basic !!!'}),
    ({}, {'Authorization': 'Bearer whatever'}),
    ({'client_id': 'demo-app', 'client_secret': SECRET}, basic()),
    ({'client_id': 'demo-app'}, basic()),
    (MultiDict([('client_id', 'demo-app'), ('client_id', 'demo-app'), ('client_secret', SECRET)]), {}),
    (MultiDict([('client_id', 'demo-app'), ('client_secret', SECRET), ('client_secret', SECRET)]), {}),
])
def test_invalid_confidential_credentials_are_challenged_before_grant_validation(app, client, form, headers):
    confidential(app)
    response = client.post(TOKEN, data=form, headers=headers)
    assert response.status_code == 401
    assert response.json == {'error': 'invalid_client'}
    assert response.headers['WWW-Authenticate'].startswith('Basic ')
    assert response.headers['Cache-Control'] == 'no-store'
    assert SECRET not in response.text


@pytest.mark.parametrize('form,headers', [
    ({'client_id': 'demo-app', 'client_secret': ''}, {}),
    ({'client_id': 'demo-app', 'client_secret': SECRET}, {}),
    ({}, basic(secret='')),
    ({}, basic()),
    ({'client_id': 'unknown'}, {}),
    ({}, {}),
])
def test_public_clients_cannot_submit_secret_credentials(client, form, headers):
    response = client.post(TOKEN, data=form, headers=headers)
    assert response.status_code == 401
    assert response.json == {'error': 'invalid_client'}


def test_public_client_cannot_be_assigned_a_secret(app):
    from mini_keycloak.services.clients import ClientService
    with app.app_context():
        client = db.session.scalar(select(Client))
        with pytest.raises(ValueError):
            ClientService(db.session).set_secret(client, SECRET)
        assert client.secret_hash is None


def test_disabled_client_fails_authentication(app, client):
    with app.app_context():
        db.session.scalar(select(Client)).enabled = False
        db.session.commit()
    response = client.post(TOKEN, data={'client_id': 'demo-app', 'grant_type': 'unknown'})
    assert response.status_code == 401
    assert response.json == {'error': 'invalid_client'}
