import pytest

from mini_keycloak.authentication.providers import ProviderRegistry
from mini_keycloak.extensions import db


def test_registry_constructs_a_fresh_provider_from_the_persisted_id(db_app):
    with db_app.app_context():
        created_with = []

        class Provider:
            pass

        class Factory:
            def create(self, session):
                created_with.append(session)
                return Provider()

        registry = ProviderRegistry({"provider-id": Factory()})

        first = registry.create("provider-id", db.session)
        second = registry.create("provider-id", db.session)

        assert isinstance(first, Provider)
        assert isinstance(second, Provider)
        assert first is not second
        assert created_with == [db.session, db.session]


def test_registry_rejects_an_unknown_persisted_provider_id(db_app):
    with db_app.app_context():
        registry = ProviderRegistry({})

        with pytest.raises(ValueError, match="Invalid authentication request"):
            registry.create("missing", db.session)
