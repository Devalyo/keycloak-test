import pytest
from sqlalchemy import event, select

from mini_keycloak.extensions import db
from mini_keycloak.models import Realm, RealmKey


def test_key_list_reports_only_safe_metadata(app):
    with app.app_context():
        key = db.session.scalar(select(RealmKey))
        kid, encrypted = key.kid, key.encrypted_private_pem
        created, activated = key.created_at.isoformat(), key.activated_at.isoformat()
    result = app.test_cli_runner().invoke(args=['realm-key-list', '--realm', 'demo'])
    assert result.exit_code == 0, result.output
    assert kid in result.output and 'RS256' in result.output and 'active' in result.output
    assert created in result.output and activated in result.output
    assert 'deactivated_at=-' in result.output
    assert encrypted not in result.output and 'PRIVATE KEY' not in result.output


@pytest.mark.parametrize('command', ['realm-key-list', 'realm-key-rotate'])
@pytest.mark.parametrize('state', ['unknown', 'disabled'])
def test_key_commands_reject_unavailable_realms_without_mutation(app, command, state):
    with app.app_context():
        before = db.session.scalar(select(RealmKey)).kid
        if state == 'disabled':
            db.session.scalar(select(Realm)).enabled = False
            db.session.commit()
    result = app.test_cli_runner().invoke(args=[command, '--realm', 'demo' if state == 'disabled' else 'missing'])
    assert result.exit_code == 1
    assert 'not found or disabled' in result.output
    assert 'Traceback' not in result.output
    with app.app_context():
        key = db.session.scalars(select(RealmKey)).one()
        assert key.kid == before and key.active


def test_key_rotation_cli_commits_retained_key_and_bootstrap_preserves_replacement(app):
    with app.app_context():
        old_kid = db.session.scalar(select(RealmKey)).kid
    runner = app.test_cli_runner()
    result = runner.invoke(args=['realm-key-rotate', '--realm', 'demo'])
    assert result.exit_code == 0, result.output
    with app.app_context():
        keys = db.session.scalars(select(RealmKey)).all()
        assert len(keys) == 2
        active = next(key for key in keys if key.active)
        retained = next(key for key in keys if not key.active)
        new_kid = active.kid
        assert retained.kid == old_kid and retained.deactivated_at is not None
        assert new_kid in result.output and new_kid != old_kid
        assert all(key.encrypted_private_pem not in result.output for key in keys)
    listing = runner.invoke(args=['realm-key-list', '--realm', 'demo'])
    assert listing.exit_code == 0
    assert old_kid in listing.output and new_kid in listing.output
    assert 'retained' in listing.output and 'active' in listing.output
    assert retained.deactivated_at.isoformat() in listing.output
    assert runner.invoke(args=['bootstrap-demo']).exit_code == 0
    assert runner.invoke(args=['bootstrap-demo']).exit_code == 0
    with app.app_context():
        assert len(db.session.scalars(select(RealmKey)).all()) == 2
        assert db.session.scalar(select(RealmKey).where(RealmKey.active.is_(True))).kid == new_kid


@pytest.mark.parametrize('stage', ['encryption', 'insert', 'commit'])
def test_failed_rotation_rolls_back_and_redacts_diagnostics(app, monkeypatch, stage):
    from mini_keycloak.services import keys as key_services

    with app.app_context():
        key = db.session.scalar(select(RealmKey))
        original = (key.kid, key.encrypted_private_pem, key.activated_at)
    secret = 'PRIVATE KEY secret-in-failed-operation'

    def fail(*args, **kwargs):
        raise RuntimeError(secret)

    if stage == 'encryption':
        monkeypatch.setattr(key_services, 'encrypt_private_pem', fail)
    elif stage == 'insert':
        event.listen(RealmKey, 'before_insert', fail)
    else:
        monkeypatch.setattr(db.session, 'commit', fail)
    try:
        result = app.test_cli_runner().invoke(args=['realm-key-rotate', '--realm', 'demo'])
    finally:
        if stage == 'insert':
            event.remove(RealmKey, 'before_insert', fail)
    assert result.exit_code == 1
    assert 'Key rotation failed' in result.output
    assert secret not in result.output and original[1] not in result.output
    assert 'Traceback' not in result.output
    with app.app_context():
        key = db.session.scalars(select(RealmKey)).one()
        assert (key.kid, key.encrypted_private_pem, key.activated_at) == original
        assert key.active and key.deactivated_at is None
