"""Persistent OIDC configuration and protocol state.

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("realms", sa.Column("issuer_override", sa.Text(), nullable=True))
    for name in (
        "access_token_lifetime_seconds", "authorization_code_lifetime_seconds",
        "refresh_token_lifetime_seconds", "sso_idle_lifetime_seconds",
        "sso_max_lifetime_seconds",
    ):
        op.add_column("realms", sa.Column(name, sa.Integer(), nullable=True))

    op.add_column("clients", sa.Column("pkce_policy", sa.String(16), nullable=False, server_default="S256"))
    op.add_column("clients", sa.Column("default_scopes", sa.JSON(), nullable=False, server_default='["openid", "profile", "email"]'))
    op.add_column("clients", sa.Column("optional_scopes", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("clients", sa.Column("post_logout_redirect_uris", sa.JSON(), nullable=False, server_default="[]"))

    op.add_column("authentication_sessions", sa.Column("response_type", sa.String(32), nullable=False, server_default="code"))
    op.add_column("authentication_sessions", sa.Column("scope", sa.Text(), nullable=False, server_default="openid"))
    op.add_column("authentication_sessions", sa.Column("state", sa.Text(), nullable=True))
    op.add_column("authentication_sessions", sa.Column("nonce", sa.Text(), nullable=True))
    op.add_column("authentication_sessions", sa.Column("code_challenge", sa.String(128), nullable=True))
    op.add_column("authentication_sessions", sa.Column("code_challenge_method", sa.String(16), nullable=True))

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("sid", sa.String(128), nullable=False),
        sa.Column("realm_id", sa.String(36), sa.ForeignKey("realms.id"), nullable=False),
        sa.Column("client_id", sa.String(36), sa.ForeignKey("clients.id"), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("auth_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_refresh_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("sid"),
    )
    for column in ("realm_id", "client_id", "user_id", "idle_expires_at", "max_expires_at"):
        op.create_index(f"ix_user_sessions_{column}", "user_sessions", [column])

    op.create_table(
        "authorization_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("realm_id", sa.String(36), sa.ForeignKey("realms.id"), nullable=False),
        sa.Column("client_id", sa.String(36), sa.ForeignKey("clients.id"), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("user_session_id", sa.String(36), sa.ForeignKey("user_sessions.id"), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("nonce", sa.Text(), nullable=True),
        sa.Column("code_challenge", sa.String(128), nullable=True),
        sa.Column("code_challenge_method", sa.String(16), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("code_hash"),
    )
    for column in ("realm_id", "client_id", "user_id", "user_session_id", "expires_at"):
        op.create_index(f"ix_authorization_codes_{column}", "authorization_codes", [column])

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("realm_id", sa.String(36), sa.ForeignKey("realms.id"), nullable=False),
        sa.Column("client_id", sa.String(36), sa.ForeignKey("clients.id"), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("user_session_id", sa.String(36), sa.ForeignKey("user_sessions.id"), nullable=False),
        sa.Column("family_id", sa.String(128), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_id", sa.String(36), sa.ForeignKey("refresh_tokens.id"), nullable=True),
        sa.UniqueConstraint("token_hash"),
    )
    for column in ("realm_id", "client_id", "user_id", "user_session_id", "family_id", "expires_at", "replaced_by_id"):
        op.create_index(f"ix_refresh_tokens_{column}", "refresh_tokens", [column])

    op.create_table(
        "realm_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("realm_id", sa.String(36), sa.ForeignKey("realms.id"), nullable=False),
        sa.Column("kid", sa.String(128), nullable=False),
        sa.Column("algorithm", sa.String(16), nullable=False),
        sa.Column("encrypted_private_pem", sa.Text(), nullable=False),
        sa.Column("public_jwk", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("realm_id", "kid"),
    )
    op.create_index("ix_realm_keys_realm_id", "realm_keys", ["realm_id"])
    op.create_index("ix_realm_keys_active", "realm_keys", ["active"])

    op.create_table(
        "security_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("realm_id", sa.String(36), sa.ForeignKey("realms.id"), nullable=False),
        sa.Column("client_id", sa.String(36), sa.ForeignKey("clients.id"), nullable=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("user_session_id", sa.String(36), sa.ForeignKey("user_sessions.id"), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_address", sa.String(45), nullable=True),
        sa.Column("error", sa.String(128), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    for column in ("realm_id", "client_id", "user_id", "user_session_id", "event_type", "created_at"):
        op.create_index(f"ix_security_events_{column}", "security_events", [column])


def downgrade():
    # Drop dependent tables before the session table they reference.
    op.drop_table("security_events")
    op.drop_table("realm_keys")
    op.drop_table("refresh_tokens")
    op.drop_table("authorization_codes")
    op.drop_table("user_sessions")
    # Native DROP COLUMN avoids rebuilding referenced identity tables on SQLite.
    for column in ("code_challenge_method", "code_challenge", "nonce", "state", "scope", "response_type"):
        op.drop_column("authentication_sessions", column)
    for column in ("post_logout_redirect_uris", "optional_scopes", "default_scopes", "pkce_policy"):
        op.drop_column("clients", column)
    for column in (
        "sso_max_lifetime_seconds", "sso_idle_lifetime_seconds", "refresh_token_lifetime_seconds",
        "authorization_code_lifetime_seconds", "access_token_lifetime_seconds", "issuer_override",
    ):
        op.drop_column("realms", column)
