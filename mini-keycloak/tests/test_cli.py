from datetime import timedelta

import pytest
from sqlalchemy import select

from mini_keycloak.extensions import db
from mini_keycloak.models import Realm, ResetEmail
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.keys import RealmKeyService


def test_bootstrap_demo_is_idempotent(db_app):
    runner = db_app.test_cli_runner()
    assert runner.invoke(args=["bootstrap-demo"]).exit_code == 0
    assert runner.invoke(args=["bootstrap-demo"]).exit_code == 0
    with db_app.app_context():
        repository = IdentityRepository(db.session)
        assert repository.get_realm("demo") is not None


@pytest.mark.parametrize("failure", ["crypto", "commit"])
def test_bootstrap_failure_rolls_back_with_safe_cli_error(db_app, monkeypatch, failure):
    secret = "bootstrap-internal-secret-sentinel"

    def fail(*args, **kwargs):
        raise RuntimeError(secret)

    with db_app.app_context():
        if failure == "crypto":
            monkeypatch.setattr(RealmKeyService, "ensure_active_key", fail)
        else:
            monkeypatch.setattr(db.session, "commit", fail)
        result = db_app.test_cli_runner().invoke(args=["bootstrap-demo"])
        assert result.exit_code != 0
        assert "Error:" in result.output
        assert secret not in result.output + repr(result.exception)
        assert "Traceback" not in result.output
        assert db.session.scalar(select(Realm)) is None


def test_outbox_list_reports_metadata_without_sensitive_action_token_hash(db_app):
    sensitive_hash = "sensitive-action-token-hash-sentinel"
    with db_app.app_context():
        repository = IdentityRepository(db.session)
        realm = repository.create_realm("outbox-audit")
        user = repository.create_user(
            realm.id,
            "audit-user",
            "audit-recipient@example.test",
            "AuditPassw0rd!",
        )
        db.session.add(
            ResetEmail(
                realm_id=realm.id,
                user_id=user.id,
                recipient="audit-recipient@example.test",
                action_token_hash=sensitive_hash,
                consumed=True,
                expires_at=utc_now() + timedelta(hours=1),
            )
        )
        db.session.commit()

    runner = db_app.test_cli_runner()
    result = runner.invoke(args=["outbox-list"])
    assert result.exit_code == 0
    assert "audit-recipient@example.test" in result.output
    assert "consumed=true" in result.output
    assert sensitive_hash not in result.output
    assert "action_token" not in result.output.casefold()
