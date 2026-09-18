from __future__ import annotations

from datetime import datetime
import re
import secrets

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from mini_keycloak.extensions import db
from mini_keycloak.models.identity import Client, Realm, User, UTCDateTime, new_id, utc_now


class AuthenticationFlow(db.Model):
    __tablename__ = "authentication_flows"
    __table_args__ = (UniqueConstraint("realm_id", "alias", name="uq_authentication_flows_realm_alias"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    realm_id: Mapped[str] = mapped_column(ForeignKey("realms.id"), index=True)
    alias: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False)
    built_in: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AuthenticationExecution(db.Model):
    __tablename__ = "authentication_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    flow_id: Mapped[str] = mapped_column(ForeignKey("authentication_flows.id"), index=True)
    authenticator: Mapped[str] = mapped_column(String(128), nullable=False)
    requirement: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)


class AuthenticationSession(db.Model):
    __tablename__ = "authentication_sessions"

    tab_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    realm_id: Mapped[str] = mapped_column(ForeignKey("realms.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    response_type: Mapped[str] = mapped_column(String(32), default="code", nullable=False)
    scope: Mapped[str] = mapped_column(Text, default="openid", nullable=False)
    state: Mapped[str | None] = mapped_column(Text)
    nonce: Mapped[str | None] = mapped_column(Text)
    code_challenge: Mapped[str | None] = mapped_column(String(128))
    code_challenge_method: Mapped[str | None] = mapped_column(String(16))
    current_execution: Mapped[str] = mapped_column(String(128), nullable=False)
    flow_id: Mapped[str | None] = mapped_column(ForeignKey("authentication_flows.id"), index=True)
    execution_status: Mapped[dict[str, str]] = mapped_column(
        MutableDict.as_mutable(JSON), default=dict, server_default="{}", nullable=False
    )
    selected_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    auth_notes: Mapped[dict[str, str]] = mapped_column(
        MutableDict.as_mutable(JSON), default=dict, nullable=False
    )
    password_update_allowed: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    realm: Mapped[Realm] = relationship()
    client: Mapped[Client] = relationship()
    selected_user: Mapped[User | None] = relationship()

    __mapper_args__ = {"version_id_col": version}


class ResetEmail(db.Model):
    __tablename__ = "reset_emails"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    realm_id: Mapped[str] = mapped_column(ForeignKey("realms.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), index=True)
    authentication_session_id: Mapped[str | None] = mapped_column(
        ForeignKey("authentication_sessions.tab_id"), index=True
    )
    token_id: Mapped[str | None] = mapped_column(String(128), unique=True)
    action_token: Mapped[str | None] = mapped_column(Text)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    action_token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False
    )
    consumed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class UserSession(db.Model):
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sid: Mapped[str] = mapped_column(String(128), default=lambda: secrets.token_urlsafe(32), unique=True, nullable=False)
    realm_id: Mapped[str] = mapped_column(ForeignKey("realms.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    auth_time: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    last_refresh_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    max_expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


def validate_sha256(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Opaque identifiers must be stored as lowercase SHA-256 hex digests")
    return value


class AuthorizationCode(db.Model):
    __tablename__ = "authorization_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    realm_id: Mapped[str] = mapped_column(ForeignKey("realms.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    user_session_id: Mapped[str] = mapped_column(ForeignKey("user_sessions.id"), index=True)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str | None] = mapped_column(Text)
    code_challenge: Mapped[str | None] = mapped_column(String(128))
    code_challenge_method: Mapped[str | None] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    @validates("code_hash")
    def validate_code_hash(self, key: str, value: str) -> str:
        return validate_sha256(value)


class RefreshToken(db.Model):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    realm_id: Mapped[str] = mapped_column(ForeignKey("realms.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    user_session_id: Mapped[str] = mapped_column(ForeignKey("user_sessions.id"), index=True)
    family_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    generation: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    replaced_by_id: Mapped[str | None] = mapped_column(ForeignKey("refresh_tokens.id"), index=True)

    @validates("token_hash")
    def validate_token_hash(self, key: str, value: str) -> str:
        return validate_sha256(value)


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    realm_id: Mapped[str] = mapped_column(ForeignKey("realms.id"), index=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    user_session_id: Mapped[str | None] = mapped_column(ForeignKey("user_sessions.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, nullable=False, index=True)
    source_address: Mapped[str | None] = mapped_column(String(45))
    error: Mapped[str | None] = mapped_column(String(128))
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class LoginFailureBucket(db.Model):
    __tablename__ = 'login_failure_buckets'
    __table_args__ = (UniqueConstraint('realm_id', 'bucket_hash',
                                     name='uq_login_failure_buckets_realm_bucket'),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    realm_id: Mapped[str] = mapped_column(ForeignKey('realms.id'), index=True)
    bucket_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False)
    first_failure_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_failure_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    blocked_until: Mapped[datetime | None] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)

    @validates('bucket_hash')
    def validate_bucket_hash(self, key: str, value: str) -> str:
        return validate_sha256(value)
