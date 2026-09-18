"""Immutable import values. Presence uses original Keycloak JSON field names."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


@dataclass(frozen=True, order=True)
class ValidationIssue:
    path: str
    message: str


@dataclass(frozen=True, order=True)
class ImportWarning:
    path: str
    message: str


@dataclass(frozen=True)
class PasswordPolicyImport:
    raw: str
    clauses: Mapping[str, int]

    def __post_init__(self):
        object.__setattr__(self, "clauses", MappingProxyType(dict(self.clauses)))


@dataclass(frozen=True)
class PasswordCredentialImport:
    value: str = field(repr=False)
    present_fields: frozenset[str]
    type: str = "password"
    temporary: bool = False

    def __post_init__(self):
        object.__setattr__(self, "present_fields", frozenset(self.present_fields))


@dataclass(frozen=True)
class UserImport:
    username: str
    username_normalized: str
    email: str | None
    email_normalized: str | None
    enabled: bool
    email_verified: bool
    first_name: str | None
    last_name: str | None
    attributes: Mapping[str, tuple[str, ...]]
    credentials: tuple[PasswordCredentialImport, ...]
    present_fields: frozenset[str]

    def __post_init__(self):
        object.__setattr__(self, "attributes", MappingProxyType({
            key: tuple(values) for key, values in self.attributes.items()
        }))
        object.__setattr__(self, "credentials", tuple(self.credentials))
        object.__setattr__(self, "present_fields", frozenset(self.present_fields))


@dataclass(frozen=True)
class ClientImport:
    client_id: str
    client_id_normalized: str
    name: str | None
    enabled: bool
    public_client: bool
    secret: str | None = field(repr=False)
    redirect_uris: tuple[str, ...]
    web_origins: tuple[str, ...]
    standard_flow_enabled: bool
    direct_access_grants_enabled: bool
    default_scopes: tuple[str, ...]
    optional_scopes: tuple[str, ...]
    attributes: Mapping[str, str]
    pkce_policy: str
    post_logout_redirect_uris: tuple[str, ...]
    present_fields: frozenset[str]

    def __post_init__(self):
        for name in ("redirect_uris", "web_origins", "default_scopes", "optional_scopes",
                     "post_logout_redirect_uris"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))
        object.__setattr__(self, "present_fields", frozenset(self.present_fields))


@dataclass(frozen=True)
class RealmImport:
    name: str
    name_normalized: str
    display_name: str | None
    enabled: bool
    forgot_password_allowed: bool
    password_grant_enabled: bool
    password_policy: PasswordPolicyImport
    access_token_lifetime_seconds: int | None
    authorization_code_lifetime_seconds: int | None
    sso_idle_lifetime_seconds: int | None
    sso_max_lifetime_seconds: int | None
    attributes: Mapping[str, str]
    clients: tuple[ClientImport, ...]
    users: tuple[UserImport, ...]
    present_fields: frozenset[str]

    def __post_init__(self):
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))
        object.__setattr__(self, "clients", tuple(self.clients))
        object.__setattr__(self, "users", tuple(self.users))
        object.__setattr__(self, "present_fields", frozenset(self.present_fields))


@dataclass(frozen=True)
class ValidationResult:
    value: RealmImport
    warnings: tuple[ImportWarning, ...]

    def __post_init__(self):
        object.__setattr__(self, "warnings", tuple(self.warnings))
