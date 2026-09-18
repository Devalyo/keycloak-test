from dataclasses import replace
from importlib.resources import files

from flask import current_app
from sqlalchemy.orm import Session

from mini_keycloak.import_export.io import read_realm_document
from mini_keycloak.import_export.validation import validate_realm_import
from mini_keycloak.models import Realm
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.realm_import import RealmImportService
from mini_keycloak.services.authentication_flows import AuthenticationFlowService


def ensure_demo_realm(session: Session) -> Realm:
    fixture = files("mini_keycloak.import_export").joinpath("fixtures/demo-realm.json")
    value = validate_realm_import(read_realm_document(fixture)).value
    # Creation still applies every DTO default/value. Empty presence sets make
    # existing entities retain operator-owned metadata; credentials have their
    # own preservation flag below. Only the legacy policy normalization follows.
    value = replace(
        value, present_fields=frozenset(), attributes={},
        clients=tuple(replace(client, present_fields=frozenset(), attributes={})
                      for client in value.clients),
        users=tuple(replace(user, present_fields=frozenset()) for user in value.users),
    )
    realm = RealmImportService(
        session, current_app.config["OIDC_KEY_ENCRYPTION_SECRET"]
    ).import_realm(value, update=True, preserve_existing_credentials=True)
    repository = IdentityRepository(session)
    client = next(client for client in repository.list_clients(realm.id)
                  if client.client_id_normalized == "demo-app")
    client.pkce_policy = "optional"
    realm.password_grant_enabled = True
    AuthenticationFlowService(session).ensure_reset_flow(realm)
    return realm
