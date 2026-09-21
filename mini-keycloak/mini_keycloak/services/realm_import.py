"""Apply validated realm imports within the caller's transaction."""

from mini_keycloak.import_export.schema import RealmImport, ValidationIssue
from mini_keycloak.import_export.validation import RealmImportValidationError
from mini_keycloak.models import Client, Realm, User
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.security.password_policy import password_satisfies_policy
from mini_keycloak.services.clients import ClientService
from mini_keycloak.services.keys import RealmKeyService
from mini_keycloak.services.authentication_flows import AuthenticationFlowService


REALM_FIELDS = {
    "displayName": "display_name", "enabled": "enabled",
    "resetPasswordAllowed": "forgot_password_allowed",
    "accessTokenLifespan": "access_token_lifetime_seconds",
    "accessCodeLifespan": "authorization_code_lifetime_seconds",
    "ssoSessionIdleTimeout": "sso_idle_lifetime_seconds",
    "ssoSessionMaxLifespan": "sso_max_lifetime_seconds",
}
CLIENT_FIELDS = {
    "name": "name", "enabled": "enabled", "publicClient": "public_client",
    "redirectUris": "redirect_uris", "webOrigins": "web_origins",
    "standardFlowEnabled": "standard_flow_enabled",
    "directAccessGrantsEnabled": "direct_access_grants_enabled",
    "defaultClientScopes": "default_scopes", "optionalClientScopes": "optional_scopes",
}
USER_FIELDS = {
    "email": "email", "enabled": "enabled", "emailVerified": "email_verified",
    "firstName": "first_name", "lastName": "last_name",
}


def _apply_fields(target, source, fields, *, creating):
    for field, attribute in fields.items():
        if creating or field in source.present_fields:
            value = getattr(source, attribute)
            setattr(target, attribute, list(value) if isinstance(value, tuple) else value)


class RealmImportError(ValueError):
    """An import failed without exposing source credentials or driver details."""


class RealmAlreadyExists(RealmImportError):
    """Updating an existing realm requires explicit opt-in."""


class RealmImportService:
    def __init__(self, session, master_secret):
        self.session = session
        self.repository = IdentityRepository(session)
        self.clients = ClientService(session)
        self.keys = RealmKeyService(session, master_secret)

    def import_realm(self, value, *, update=False, preserve_existing_credentials=False):
        """Flush one validated DTO; never commit, delete unlisted data, or log input.

        The caller owns the transaction. Failure rolls back that entire
        transaction, including any work the caller performed before this call.
        Entry requires no pending new, dirty, or deleted caller-owned objects;
        rejecting them also rolls back before any import reads or writes.
        Parser warnings stay with ValidationResult at the I/O boundary.
        Credential preservation includes absence on existing entities; newly
        created entities still receive supplied initial credentials.
        """
        try:
            if self.session.new or self.session.dirty or self.session.deleted:
                raise RealmImportError("Realm import requires a clean session")
            if not isinstance(value, RealmImport):
                raise RealmImportError("A validated realm import is required")
            with self.session.no_autoflush:
                realm, clients, users = self._preflight(
                    value, update=update, preserve=preserve_existing_credentials)
            creating = realm is None
            if creating:
                realm = Realm(name=value.name)
                self.session.add(realm)
            _apply_fields(realm, value, REALM_FIELDS, creating=creating)
            if creating or "passwordPolicy" in value.present_fields:
                realm.password_policy = {"raw": value.password_policy.raw,
                                         "clauses": dict(value.password_policy.clauses)}
            if creating or "mini.keycloak.passwordGrantEnabled" in value.attributes:
                realm.password_grant_enabled = value.password_grant_enabled
            # Release changing unique email slots together before assigning the
            # validated final ownership (including swaps). Rollback restores them.
            for user in value.users:
                existing = users.get(user.username_normalized)
                if (existing is not None and "email" in user.present_fields
                        and existing.email_normalized != user.email_normalized):
                    existing.email_normalized = None
            self.session.flush()
            for client in value.clients:
                self._apply_client(realm, client, clients.get(client.client_id_normalized),
                                   preserve_existing_credentials)
            for user in value.users:
                self._apply_user(realm, user, users.get(user.username_normalized),
                                 preserve_existing_credentials)
            self.keys.ensure_active_key(realm.id)
            AuthenticationFlowService(self.session).ensure_reset_flow(realm)
            self.session.flush()
            return realm
        except (RealmImportError, RealmImportValidationError) as exc:
            self.session.rollback()
            if isinstance(exc, RealmImportValidationError):
                error = RealmImportValidationError(exc.errors)
            else:
                error = type(exc)(str(exc))
        except Exception:
            # Driver and crypto exceptions can contain input values or SQL
            # parameters. Raise outside the handler to avoid retaining a chain.
            self.session.rollback()
            error = RealmImportError("Realm import failed")
        finally:
            # Tracebacks may outlive the operation. Drop our references to
            # credentials, including the final loop's client/user DTOs.
            value = client = user = None
        raise error from None

    def _preflight(self, value, *, update, preserve):
        matches = self.repository.realms_with_normalized_name(value.name_normalized)
        if matches and not update:
            raise RealmAlreadyExists("Realm already exists; explicit update is required")
        if len(matches) > 1:
            raise RealmImportValidationError([
                ValidationIssue("$.realm", "Ambiguous normalized identifier")])
        realm = matches[0] if matches else None
        clients = {}
        users = {}
        errors = []
        if realm is not None:
            for client in self.repository.list_clients(realm.id):
                key = client.client_id_normalized
                if key in clients:
                    errors.append(ValidationIssue("$.clients", "Ambiguous normalized identifier"))
                clients[key] = client
            users = {user.username_normalized: user for user in self.repository.list_users(realm.id)}

        for index, client in enumerate(value.clients):
            existing = clients.get(client.client_id_normalized)
            public = (client.public_client if existing is None or "publicClient" in client.present_fields
                      else existing.public_client)
            path = f"$.clients[{index}].secret"
            if public and client.secret is not None:
                errors.append(ValidationIssue(path, "Public clients must not have secrets"))
            elif (not public and client.secret is None
                  and (existing is None or (not preserve and not existing.secret_hash))):
                errors.append(ValidationIssue(path, "Confidential clients require a secret"))

        policy = (value.password_policy.clauses
                  if realm is None or "passwordPolicy" in value.present_fields
                  else realm.password_policy.get("clauses", {}))
        for index, user in enumerate(value.users):
            if user.credentials and not (preserve and user.username_normalized in users):
                if not password_satisfies_policy(user.credentials[0].value, policy):
                    errors.append(ValidationIssue(
                        f"$.users[{index}].credentials[0].value",
                        "Password does not satisfy realm policy"))

        # Validate the final email ownership, including omitted/unlisted users.
        incoming = {user.username_normalized: user for user in value.users}
        emails = {}
        for key, user in users.items():
            change = incoming.get(key)
            if change is None or "email" not in change.present_fields:
                if user.email_normalized:
                    emails[user.email_normalized] = key
        for index, user in enumerate(value.users):
            if user.username_normalized in users and "email" not in user.present_fields:
                continue
            email = user.email_normalized
            if email and email in emails and emails[email] != user.username_normalized:
                errors.append(ValidationIssue(f"$.users[{index}].email", "Duplicate normalized identifier"))
            elif email:
                emails[email] = user.username_normalized
        if errors:
            raise RealmImportValidationError(errors)
        return realm, clients, users

    def _apply_client(self, realm, value, client, preserve):
        creating = client is None
        if creating:
            client = Client(realm_id=realm.id, client_id=value.client_id)
            self.session.add(client)
        _apply_fields(client, value, CLIENT_FIELDS, creating=creating)
        if creating or "pkce.code.challenge.method" in value.attributes:
            client.pkce_policy = value.pkce_policy
        if creating or "post.logout.redirect.uris" in value.attributes:
            client.post_logout_redirect_uris = list(value.post_logout_redirect_uris)
        if preserve and not creating:
            return
        if client.public_client:
            client.secret_hash = None
        elif value.secret is not None:
            self.clients.set_secret(client, value.secret)

    def _apply_user(self, realm, value, user, preserve):
        creating = user is None
        if creating:
            user = User(realm_id=realm.id, username=value.username,
                        username_normalized=value.username_normalized)
            self.session.add(user)
        _apply_fields(user, value, USER_FIELDS, creating=creating)
        if creating or "email" in value.present_fields:
            user.email_normalized = value.email_normalized
        if creating or "attributes" in value.present_fields:
            user.attributes = {key: list(values) for key, values in value.attributes.items()}
        self.session.flush()
        if value.credentials and (creating or not preserve):
            self.repository.set_password(user, value.credentials[0].value)
