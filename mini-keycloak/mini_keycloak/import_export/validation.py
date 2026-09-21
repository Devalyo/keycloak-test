"""Validate decoded Keycloak-style JSON without I/O or database access.

The structural pass bounds even ignored fields. Domain validation accumulates
all errors within those budgets; only a complete valid document is returned.
"""
from __future__ import annotations

import json
import math
import re
from ipaddress import IPv4Address, IPv6Address
from types import MappingProxyType
from urllib.parse import urlsplit

from .schema import (
    ClientImport, ImportWarning, PasswordCredentialImport, PasswordPolicyImport,
    RealmImport, UserImport, ValidationIssue, ValidationResult,
)


MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_NODES = 50000
MAX_DEPTH = 16
MAX_ENTITIES = 1000
MAX_LIST = 256
MAX_ATTRIBUTES = 64
MAX_SECRET = 4096
SUPPORTED_SCOPES = frozenset({"openid", "profile", "email"})
REALM_FIELDS = frozenset({
    "realm", "displayName", "enabled", "resetPasswordAllowed", "passwordPolicy",
    "accessTokenLifespan", "accessCodeLifespan", "ssoSessionIdleTimeout",
    "ssoSessionMaxLifespan", "attributes", "clients", "users",
})
CLIENT_FIELDS = frozenset({
    "clientId", "name", "enabled", "publicClient", "secret", "redirectUris",
    "webOrigins", "standardFlowEnabled", "directAccessGrantsEnabled",
    "defaultClientScopes", "optionalClientScopes", "attributes",
})
USER_FIELDS = frozenset({
    "username", "email", "enabled", "emailVerified", "firstName", "lastName",
    "attributes", "credentials",
})
CREDENTIAL_FIELDS = frozenset({"type", "value", "temporary"})
REALM_ATTRIBUTES = frozenset({"mini.keycloak.passwordGrantEnabled"})
CLIENT_ATTRIBUTES = frozenset({"pkce.code.challenge.method", "post.logout.redirect.uris"})
POLICY_CLAUSES = frozenset({"length", "digits", "lowerCase", "upperCase", "specialChars"})
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
URI_PATH = re.compile(r"(?:[A-Za-z0-9._~!$&'()+,;=:@/\-]|%[0-9A-Fa-f]{2})*")
URI_QUERY = re.compile(r"(?:[A-Za-z0-9._~!$&'()+,;=:@/?\-]|%[0-9A-Fa-f]{2})*")
HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def _valid_http_authority(authority):
    """Accept DNS, canonical IPv4, or bracketed IPv6 without rewriting input."""
    if authority.startswith("["):
        match = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::([0-9]+))?", authority)
        if not match:
            return False
        host, port = match.groups()
        IPv6Address(host)  # Also excludes zone identifiers and IPvFuture literals.
    else:
        match = re.fullmatch(r"([^:]+)(?::([0-9]+))?", authority)
        if not match:
            return False
        host, port = match.groups()
        labels = host.split(".")
        if len(host) > 253 or any(not HOST_LABEL.fullmatch(label) for label in labels):
            return False
        # Browsers interpret hosts ending in a number as IPv4. Require the
        # ordinary dotted-decimal spelling instead of octal/hex/short forms.
        if re.fullmatch(r"[0-9]+|0[xX][0-9A-Fa-f]*", labels[-1]):
            IPv4Address(host)
    return port is None or (str(int(port)) == port and int(port) <= 65535)


class RealmImportValidationError(ValueError):
    """Only fixed public messages and paths; never retain input or partial DTOs."""

    def __init__(self, errors):
        self.errors = tuple(sorted(set(errors)))
        super().__init__("; ".join(f"{issue.path}: {issue.message}" for issue in self.errors))


def check_document_structure(document):
    """Bound decoded JSON iteratively, including values in ignored fields."""
    stack = [(document, 0)]
    nodes = 0
    size = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise RealmImportValidationError([ValidationIssue("$", "Document exceeds structural limits")])
        kind = type(value)
        if kind is dict:
            if len(value) > MAX_NODES:
                raise RealmImportValidationError([ValidationIssue("$", "Document exceeds structural limits")])
            for key, item in value.items():
                if type(key) is not str or not 1 <= len(key) <= 255 or CONTROL.search(key):
                    raise RealmImportValidationError([ValidationIssue("$", "Object keys must be bounded strings without control characters")])
                size += len(key.encode("utf-8")) + 4
                stack.append((item, depth + 1))
        elif kind is list:
            if len(value) > MAX_NODES:
                raise RealmImportValidationError([ValidationIssue("$", "Document exceeds structural limits")])
            stack.extend((item, depth + 1) for item in value)
        elif kind is str:
            if len(value) > MAX_DOCUMENT_BYTES or CONTROL.search(value):
                raise RealmImportValidationError([ValidationIssue("$", "Document contains an invalid or oversized string")])
            size += len(value.encode("utf-8")) + 2
        elif kind not in (int, float, bool, type(None)) or (kind is float and not math.isfinite(value)):
            raise RealmImportValidationError([ValidationIssue("$", "Document must contain only JSON values")])
        size += 1
        if size > MAX_DOCUMENT_BYTES:
            raise RealmImportValidationError([ValidationIssue("$", "Document exceeds size limit")])


def _path(parent, key):
    # JSON escaping preserves arbitrary field identity without allowing literal
    # dots, brackets, quotes, or Unicode direction controls to alter the path.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return f"{parent}.{key}"
    return f"{parent}[{json.dumps(key, ensure_ascii=True)}]"


class _Validator:
    def __init__(self, update):
        self.update = update
        self.errors = []
        self.warnings = []

    def error(self, path, message):
        self.errors.append(ValidationIssue(path, message))

    def unknown(self, obj, allowed, path, *, reject=False):
        for key in sorted(obj.keys() - allowed):
            if reject:
                self.error(_path(path, key), "Unsupported credential field")
            else:
                self.warnings.append(ImportWarning(_path(path, key), "Unsupported field is ignored"))

    def obj(self, value, path, *, maximum=None):
        if type(value) is not dict:
            self.error(path, "Expected an object")
            return {}
        if maximum is not None and len(value) > maximum:
            self.error(path, "Too many object entries")
            return {}
        return value

    def sequence(self, value, path, *, maximum=MAX_LIST):
        if type(value) is not list:
            self.error(path, "Expected a list")
            return []
        if len(value) > maximum:
            self.error(path, "Too many list entries")
            return []
        return value

    def string(self, value, path, *, maximum=255, empty=False, nullable=False, strip=False):
        if value is None and nullable:
            return None
        if type(value) is not str:
            self.error(path, "Expected a string")
            return ""
        if len(value) > maximum or CONTROL.search(value):
            self.error(path, "String exceeds limit or contains control characters")
        result = value.strip() if strip else value
        if not empty and not result:
            self.error(path, "String must not be empty")
        if strip and len(result.casefold()) > maximum:
            self.error(path, "Normalized identifier exceeds length limit")
        return result

    def boolean(self, obj, key, path, default):
        value = obj.get(key, default)
        if type(value) is not bool:
            self.error(f"{path}.{key}", "Expected a boolean")
            return default
        return value

    def lifetime(self, obj, key):
        if key not in obj:
            return None
        value = obj[key]
        if type(value) is not int or not 1 <= value <= 2147483647:
            self.error(f"$.{key}", "Expected a positive 32-bit integer")
            return None
        return value

    def strings(self, value, path, *, maximum=MAX_LIST, length=2048):
        return tuple(self.string(item, f"{path}[{i}]", maximum=length)
                     for i, item in enumerate(self.sequence(value, path, maximum=maximum)))

    def uri(self, value, path, *, origin=False):
        if origin and value == "+":
            return
        try:
            parsed = urlsplit(value)
            valid = (parsed.scheme in {"http", "https"}
                     and _valid_http_authority(parsed.netloc)
                     and "#" not in value
                     and "*" not in value and "\\" not in value
                     and not any(ch.isspace() for ch in value)
                     and not CONTROL.search(value)
                     and URI_PATH.fullmatch(parsed.path) is not None
                     and URI_QUERY.fullmatch(parsed.query) is not None)
            # Literal and percent-encoded dot segments are normalized by URL
            # consumers, so cannot serve as exact registered redirect paths.
            segments = re.sub(r"%2e", ".", parsed.path, flags=re.IGNORECASE).split("/")
            valid = valid and not any(segment in {".", ".."} for segment in segments)
            if origin:
                valid = valid and not parsed.path and not parsed.query and "?" not in value
        except ValueError:
            valid = False
        if not valid:
            self.error(path, "Expected an exact HTTP(S) origin" if origin else "Expected an exact absolute HTTP(S) URI")

    def uris(self, value, path, *, origin=False):
        result = self.strings(value, path)
        for i, item in enumerate(result):
            self.uri(item, f"{path}[{i}]", origin=origin)
        return result

    def scopes(self, value, path):
        result = self.strings(value, path, length=255)
        for i, item in enumerate(result):
            if item not in SUPPORTED_SCOPES:
                self.error(f"{path}[{i}]", "Unsupported scope")
        return tuple(dict.fromkeys(result))

    def attributes(self, value, path, supported=None):
        obj = self.obj(value, path, maximum=MAX_ATTRIBUTES)
        if supported is not None:
            self.unknown(obj, supported, path)
        result = {}
        for key, item in obj.items():
            item_path = _path(path, key)
            if supported is None:
                result[key] = self.strings(item, item_path, maximum=64)
            else:
                parsed = self.string(item, item_path, maximum=4096, empty=True)
                if key in supported:
                    result[key] = parsed
        return MappingProxyType(result)

    def policy(self, value):
        raw = self.string(value, "$.passwordPolicy", maximum=4096, empty=True)
        clauses = {}
        if raw.strip():
            for i, clause in enumerate(re.split(r"\s+and\s+", raw.strip())):
                path = f"$.passwordPolicy[{i}]"
                match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)\(([^()]*)\)", clause.strip())
                if match is None:
                    self.error(path, "Malformed password policy clause")
                    continue
                name, argument = match.groups()
                if name not in POLICY_CLAUSES:
                    self.warnings.append(ImportWarning(path, "Unsupported password policy clause is ignored"))
                    continue
                if not re.fullmatch(r"[0-9]{1,4}", argument) or not (1 if name == "length" else 0) <= int(argument) <= MAX_SECRET:
                    self.error(path, "Invalid password policy clause value")
                elif name in clauses:
                    self.error(path, "Duplicate password policy clause")
                else:
                    clauses[name] = int(argument)
        return PasswordPolicyImport(raw, MappingProxyType(clauses))

    def credential(self, value, path):
        obj = self.obj(value, path)
        self.unknown(obj, CREDENTIAL_FIELDS, path, reject=True)
        if obj.get("type") != "password":
            self.error(f"{path}.type", "Only password credentials are supported")
        password = self.string(obj.get("value"), f"{path}.value", maximum=MAX_SECRET)
        temporary = self.boolean(obj, "temporary", path, False)
        if temporary:
            self.error(f"{path}.temporary", "Temporary password credentials are unsupported")
        return PasswordCredentialImport(password, frozenset(obj))

    def user(self, value, path):
        obj = self.obj(value, path)
        self.unknown(obj, USER_FIELDS, path)
        username = self.string(obj.get("username"), f"{path}.username", strip=True)
        email = self.string(obj.get("email"), f"{path}.email", maximum=320, nullable=True, strip=True)
        if email and not re.fullmatch(r"[^\s@]+@[^\s@]+", email):
            self.error(f"{path}.email", "Expected an email address")
        credentials = tuple(self.credential(item, f"{path}.credentials[{i}]")
                            for i, item in enumerate(self.sequence(obj.get("credentials", []), f"{path}.credentials", maximum=1)))
        return UserImport(
            username=username, username_normalized=username.casefold(), email=email,
            email_normalized=email.casefold() if email else None,
            enabled=self.boolean(obj, "enabled", path, True),
            email_verified=self.boolean(obj, "emailVerified", path, False),
            first_name=self.string(obj.get("firstName"), f"{path}.firstName", empty=True, nullable=True),
            last_name=self.string(obj.get("lastName"), f"{path}.lastName", empty=True, nullable=True),
            attributes=self.attributes(obj.get("attributes", {}), f"{path}.attributes"),
            credentials=credentials, present_fields=frozenset(obj),
        )

    def client(self, value, path):
        if type(value) is not dict:
            self.error(path, "Expected an object")
            return None
        obj = value
        self.unknown(obj, CLIENT_FIELDS, path)
        client_id = self.string(obj.get("clientId"), f"{path}.clientId", strip=True)
        public = self.boolean(obj, "publicClient", path, True)
        secret = None
        if "secret" in obj:
            secret = self.string(obj["secret"], f"{path}.secret", maximum=MAX_SECRET)
            if public and (not self.update or "publicClient" in obj):
                self.error(f"{path}.secret", "Public clients must not have secrets")
        elif not public and not self.update:
            self.error(f"{path}.secret", "Confidential clients require a secret")
        attributes = self.attributes(obj.get("attributes", {}), f"{path}.attributes", CLIENT_ATTRIBUTES)
        pkce = attributes.get("pkce.code.challenge.method", "S256")
        if pkce not in {"S256", "optional"}:
            self.error(_path(f"{path}.attributes", "pkce.code.challenge.method"), "Unsupported PKCE policy")
        logout_raw = attributes.get("post.logout.redirect.uris", "")
        logout = self.uris(logout_raw.split("##") if logout_raw else [], _path(f"{path}.attributes", "post.logout.redirect.uris"))
        return ClientImport(
            client_id=client_id, client_id_normalized=client_id.casefold(),
            name=self.string(obj.get("name"), f"{path}.name", empty=True, nullable=True),
            enabled=self.boolean(obj, "enabled", path, True), public_client=public, secret=secret,
            redirect_uris=self.uris(obj.get("redirectUris", []), f"{path}.redirectUris"),
            web_origins=self.uris(obj.get("webOrigins", []), f"{path}.webOrigins", origin=True),
            standard_flow_enabled=self.boolean(obj, "standardFlowEnabled", path, True),
            direct_access_grants_enabled=self.boolean(obj, "directAccessGrantsEnabled", path, False),
            default_scopes=self.scopes(obj.get("defaultClientScopes", ["openid", "profile", "email"]), f"{path}.defaultClientScopes"),
            optional_scopes=self.scopes(obj.get("optionalClientScopes", []), f"{path}.optionalClientScopes"),
            attributes=attributes, pkce_policy=pkce, post_logout_redirect_uris=logout,
            present_fields=frozenset(obj),
        )

    def entities(self, value, path, parser, unique_fields):
        result = []
        seen = {normalized: set() for normalized, _ in unique_fields}
        for i, item in enumerate(self.sequence(value, path, maximum=MAX_ENTITIES)):
            parsed = parser(item, f"{path}[{i}]")
            if parsed is None:
                continue
            result.append(parsed)
            for normalized, source in unique_fields:
                key = getattr(parsed, normalized)
                if key:
                    if key in seen[normalized]:
                        self.error(f"{path}[{i}].{source}", "Duplicate normalized identifier")
                    seen[normalized].add(key)
        return tuple(result)

    def realm(self, document):
        obj = self.obj(document, "$")
        self.unknown(obj, REALM_FIELDS, "$")
        name = self.string(obj.get("realm"), "$.realm", strip=True)
        if name and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or ".." in name):
            self.error("$.realm", "Realm name must be a safe path segment")
        attributes = self.attributes(obj.get("attributes", {}), "$.attributes", REALM_ATTRIBUTES)
        grant = attributes.get("mini.keycloak.passwordGrantEnabled", "false")
        if grant not in {"true", "false"}:
            self.error(_path("$.attributes", "mini.keycloak.passwordGrantEnabled"), "Expected a true or false string")
        return RealmImport(
            name=name, name_normalized=name.casefold(),
            display_name=self.string(obj.get("displayName"), "$.displayName", empty=True, nullable=True),
            enabled=self.boolean(obj, "enabled", "$", True),
            forgot_password_allowed=self.boolean(obj, "resetPasswordAllowed", "$", True),
            password_grant_enabled=grant == "true",
            password_policy=self.policy(obj.get("passwordPolicy", "")),
            access_token_lifetime_seconds=self.lifetime(obj, "accessTokenLifespan"),
            authorization_code_lifetime_seconds=self.lifetime(obj, "accessCodeLifespan"),
            sso_idle_lifetime_seconds=self.lifetime(obj, "ssoSessionIdleTimeout"),
            sso_max_lifetime_seconds=self.lifetime(obj, "ssoSessionMaxLifespan"),
            attributes=attributes,
            clients=self.entities(obj.get("clients", []), "$.clients", self.client, [("client_id_normalized", "clientId")]),
            users=self.entities(obj.get("users", []), "$.users", self.user, [("username_normalized", "username"), ("email_normalized", "email")]),
            present_fields=frozenset(obj),
        )


def validate_realm_import(document, *, update=False) -> ValidationResult:
    """Validate one realm. Updates defer omitted secret requirements to the DB service.

    That service must check the effective client type and require a secret for
    newly created confidential clients, even when update=True.
    """
    try:
        check_document_structure(document)
        validator = _Validator(update)
        value = validator.realm(document)
        if validator.errors:
            raise RealmImportValidationError(validator.errors)
        return ValidationResult(value, tuple(sorted(validator.warnings)))
    except RealmImportValidationError as exc:
        # Recreate the public error so no parsing frame or partial DTO survives
        # in its traceback. Diagnostics contain paths and fixed categories only.
        error = RealmImportValidationError(exc.errors)
    finally:
        document = value = validator = None
    raise error from None
