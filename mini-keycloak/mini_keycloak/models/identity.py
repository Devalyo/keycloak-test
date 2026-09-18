from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates
from sqlalchemy.types import TypeDecorator

from mini_keycloak.extensions import db


def new_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Persist UTC and restore timezone information stripped by SQLite."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Protocol timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Realm(db.Model):
    __tablename__ = "realms"
    __table_args__ = (UniqueConstraint("name_normalized", name="uq_realms_name_normalized"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    # Unicode casefold can expand one source character into three characters.
    name_normalized: Mapped[str] = mapped_column(String(765), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    forgot_password_allowed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    password_grant_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    password_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    issuer_override: Mapped[str | None] = mapped_column(Text)
    access_token_lifetime_seconds: Mapped[int | None] = mapped_column(Integer)
    authorization_code_lifetime_seconds: Mapped[int | None] = mapped_column(Integer)
    refresh_token_lifetime_seconds: Mapped[int | None] = mapped_column(Integer)
    sso_idle_lifetime_seconds: Mapped[int | None] = mapped_column(Integer)
    sso_max_lifetime_seconds: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    @validates("name")
    def normalize_name(self, key, value):
        self.name_normalized = value.strip().casefold()
        return value


class Client(db.Model):
    __tablename__ = "clients"
    __table_args__ = (
        UniqueConstraint("realm_id", "client_id"),
        UniqueConstraint("realm_id", "client_id_normalized", name="uq_clients_realm_client_id_normalized"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    realm_id: Mapped[str] = mapped_column(ForeignKey("realms.id"), index=True)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_id_normalized: Mapped[str] = mapped_column(String(765), nullable=False)
    name: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    public_client: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    secret_hash: Mapped[str | None] = mapped_column(Text)
    redirect_uris: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    web_origins: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    pkce_policy: Mapped[str] = mapped_column(String(16), default="S256", nullable=False)
    default_scopes: Mapped[list[str]] = mapped_column(
        JSON, default=lambda: ["openid", "profile", "email"], nullable=False
    )
    optional_scopes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    post_logout_redirect_uris: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    standard_flow_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    direct_access_grants_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    realm: Mapped[Realm] = relationship()

    @validates("client_id")
    def normalize_client_id(self, key, value):
        self.client_id_normalized = value.strip().casefold()
        return value


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("realm_id", "username_normalized"),
        UniqueConstraint("realm_id", "email_normalized"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    realm_id: Mapped[str] = mapped_column(ForeignKey("realms.id"), index=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    username_normalized: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320))
    email_normalized: Mapped[str | None] = mapped_column(String(320))
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    first_name: Mapped[str | None] = mapped_column(String(255))
    last_name: Mapped[str | None] = mapped_column(String(255))
    attributes: Mapped[dict[str, list[str]]] = mapped_column(
        JSON, default=dict, server_default="{}", nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    @validates("first_name", "last_name")
    def validate_profile_name(self, key, value):
        if value is not None and (type(value) is not str or len(value) > 255):
            raise ValueError("Profile name must be a string of at most 255 characters")
        return value

    @validates("attributes")
    def validate_attributes(self, key, value):
        if type(value) is not dict or len(value) > 64:
            raise ValueError("Attributes must be an object with at most 64 entries")
        for name, values in value.items():
            if type(name) is not str or not 1 <= len(name) <= 255:
                raise ValueError("Attribute names must contain 1 to 255 characters")
            if type(values) is not list or len(values) > 64:
                raise ValueError("Attribute values must be a list of at most 64 strings")
            if any(type(item) is not str or len(item) > 2048 for item in values):
                raise ValueError("Attribute values must be strings of at most 2048 characters")
        return {name: list(values) for name, values in value.items()}


class Credential(db.Model):
    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("user_id", "type"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    type: Mapped[str] = mapped_column(String(32), default="password", nullable=False)
    secret_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class RealmKey(db.Model):
    __tablename__ = "realm_keys"
    __table_args__ = (UniqueConstraint("realm_id", "kid"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    realm_id: Mapped[str] = mapped_column(ForeignKey("realms.id"), index=True)
    kid: Mapped[str] = mapped_column(String(128), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), default="RS256", nullable=False)
    encrypted_private_pem: Mapped[str] = mapped_column(Text, nullable=False)
    public_jwk: Mapped[dict] = mapped_column(JSON, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    activated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    deactivated_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
