from pathlib import Path

import click
from flask import Flask, current_app
from sqlalchemy import select

from mini_keycloak.extensions import db
from mini_keycloak.import_export.io import RealmImportIOError, read_realm_document
from mini_keycloak.import_export.validation import RealmImportValidationError, validate_realm_import
from mini_keycloak.models import ResetEmail
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.bootstrap import ensure_demo_realm
from mini_keycloak.services.keys import RealmKeyRealmUnavailable, RealmKeyService
from mini_keycloak.services.realm_import import RealmAlreadyExists, RealmImportService


def register_cli(app: Flask) -> None:
    @app.cli.command('admin-bootstrap')
    @click.option('--username', required=True)
    @click.password_option()
    def admin_bootstrap(username: str, password: str) -> None:
        try:
            repository = IdentityRepository(db.session)
            existing = repository.get_realm('master')
            if existing is not None and any(
                    user.username_normalized == username.strip().casefold()
                    for user in repository.list_users(existing.id)):
                raise ValueError()
            document = {
                'realm': 'master',
                'enabled': True,
                'attributes': {'mini.keycloak.passwordGrantEnabled': 'true'},
                'clients': [{'clientId': 'admin-cli', 'enabled': True,
                             'publicClient': True, 'directAccessGrantsEnabled': True}],
                'users': [{'username': username, 'attributes': {'realmRoles': ['admin']},
                           'credentials': [{'type': 'password', 'value': password}]}],
            }
            value = validate_realm_import(document, update=existing is not None).value
            RealmImportService(
                db.session, current_app.config['OIDC_KEY_ENCRYPTION_SECRET']
            ).import_realm(value, update=existing is not None)
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise click.ClickException('Admin bootstrap failed') from None
        click.echo('master realm and admin identity are ready')

    def key_operation(realm_name: str, *, rotate: bool) -> None:
        try:
            realm = IdentityRepository(db.session).get_realm(realm_name)
            if realm is None or not realm.enabled:
                raise RealmKeyRealmUnavailable("Realm not found or disabled")
            service = RealmKeyService(db.session, current_app.config["OIDC_KEY_ENCRYPTION_SECRET"])
            keys = [service.rotate_active_key(realm.id)] if rotate else service.list_keys(realm.id)
            lines = [
                f"kid={key.kid} algorithm={key.algorithm} status={key.status} "
                f"created_at={key.created_at.isoformat()} activated_at={key.activated_at.isoformat()} "
                f"deactivated_at={key.deactivated_at.isoformat() if key.deactivated_at else '-'}"
                for key in keys
            ]
            if rotate:
                db.session.commit()
            else:
                db.session.rollback()
        except RealmKeyRealmUnavailable:
            db.session.rollback()
            error = "Realm not found or disabled"
        except Exception:
            db.session.rollback()
            error = "Key rotation failed" if rotate else "Key listing failed"
        else:
            for line in lines:
                click.echo(line)
            return
        raise click.ClickException(error) from None

    @app.cli.command("realm-key-list")
    @click.option("--realm", required=True, help="Realm name.")
    def realm_key_list(realm: str) -> None:
        """List active and retained signing-key metadata."""
        key_operation(realm, rotate=False)

    @app.cli.command("realm-key-rotate")
    @click.option("--realm", required=True, help="Realm name.")
    def realm_key_rotate(realm: str) -> None:
        """Activate a new signing key and retain previous verification keys."""
        key_operation(realm, rotate=True)

    @app.cli.command("realm-import")
    @click.argument("path", type=Path)
    @click.option("--update", is_flag=True, help="Update listed fields without deleting unlisted entities.")
    def realm_import(path: Path, update: bool) -> None:
        """Import a UTF-8 Keycloak-style realm JSON file (maximum 2 MiB)."""
        try:
            result = validate_realm_import(read_realm_document(path), update=update)
            realm = RealmImportService(
                db.session, current_app.config["OIDC_KEY_ENCRYPTION_SECRET"]
            ).import_realm(result.value, update=update)
            summary = (f"realm {realm.name} imported: clients={len(result.value.clients)} "
                       f"users={len(result.value.users)}")
            warnings = result.warnings
            result = None
            db.session.commit()
        except (RealmImportIOError, RealmImportValidationError) as exc:
            db.session.rollback()
            error = str(exc)
        except RealmAlreadyExists:
            db.session.rollback()
            error = "Realm already exists; use --update to update it"
        except Exception:
            db.session.rollback()
            error = "Realm import failed"
        else:
            click.echo(summary)
            for warning in sorted(warnings):
                click.echo(f"Warning: {warning.path}: {warning.message}")
            return
        finally:
            result = None
        raise click.ClickException(error) from None

    @app.cli.command('cleanup-expired')
    @click.option('--batch-size', type=click.IntRange(1, 1000), default=100, show_default=True)
    def cleanup_expired_command(batch_size):
        from mini_keycloak.services.cleanup import cleanup_expired
        counts = cleanup_expired(db.session, batch_size=batch_size)
        click.echo(' '.join(f'{name}={count}' for name, count in counts.items()))

    @app.cli.command("bootstrap-demo")
    def bootstrap_demo() -> None:
        try:
            realm = ensure_demo_realm(db.session)
            summary = f"realm {realm.name} is ready"
            db.session.commit()
        except Exception:
            db.session.rollback()
        else:
            click.echo(summary)
            return
        raise click.ClickException("Realm bootstrap failed") from None

    @app.cli.command("outbox-list")
    def outbox_list() -> None:
        messages = db.session.scalars(
            select(ResetEmail).order_by(ResetEmail.created_at.desc())
        )
        for message in messages:
            click.echo(
                f"{message.created_at.isoformat()} recipient={message.recipient} "
                f"consumed={str(message.consumed).lower()}"
            )
