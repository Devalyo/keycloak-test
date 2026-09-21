from sqlalchemy import case, event
from sqlalchemy.orm import Session

from mini_keycloak.extensions import db
from mini_keycloak.models import User
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.bootstrap import ensure_demo_realm


def test_bootstrap_is_idempotent_and_realm_scoped(db_app):
    with db_app.app_context():
        first = ensure_demo_realm(db.session)
        db.session.commit()
        second = ensure_demo_realm(db.session)
        db.session.commit()

        repository = IdentityRepository(db.session)
        assert first.id == second.id
        assert repository.get_client(first.id, "demo-app").redirect_uris == [
            "http://localhost:9999/callback"
        ]
        demo_user = repository.find_user(first.id, "DEMO-USER@EXAMPLE.TEST")
        assert demo_user is not None
        assert repository.password_matches(demo_user, "DemoPassw0rd!")
        assert not repository.password_matches(demo_user, "wrong")


def test_same_username_can_exist_in_different_realms(db_app):
    with db_app.app_context():
        repository = IdentityRepository(db.session)
        realm_a = repository.create_realm("a")
        realm_b = repository.create_realm("b")
        repository.create_user(realm_a.id, "shared", "a@example.test", "Password1!")
        repository.create_user(realm_b.id, "shared", "b@example.test", "Password2!")
        db.session.commit()
        assert repository.find_user(realm_a.id, "shared").email == "a@example.test"
        assert repository.find_user(realm_b.id, "shared").email == "b@example.test"


def test_find_user_prefers_username_when_email_match_is_returned_first(db_app):
    normalized = "shared-identifier"
    with db_app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.create_realm("collision")
        email_match = repository.create_user(
            realm.id,
            "email-owner",
            normalized,
            "Password1!",
        )
        username_match = repository.create_user(
            realm.id,
            normalized,
            "username-owner@example.test",
            "Password2!",
        )
        db.session.commit()
        realm_id = realm.id
        email_match_id = email_match.id
        username_match_id = username_match.id
        db.session.remove()

        with Session(db.engine) as adversarial_session:
            @event.listens_for(adversarial_session, "do_orm_execute")
            def order_email_match_first(execute_state):
                if execute_state.is_select:
                    execute_state.statement = execute_state.statement.order_by(
                        case(
                            (User.email_normalized == normalized, 0),
                            else_=1,
                        )
                    )

            found = IdentityRepository(adversarial_session).find_user(
                realm_id, f"  {normalized.upper()}  "
            )

        assert found is not None
        assert found.id == username_match_id
        assert found.id != email_match_id
