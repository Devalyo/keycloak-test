"""identity foundation

Revision ID: 0001
Revises:

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "realms",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("forgot_password_allowed", sa.Boolean(), nullable=False),
        sa.Column("password_policy", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "clients",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("realm_id", sa.String(length=36), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("public_client", sa.Boolean(), nullable=False),
        sa.Column("secret_hash", sa.Text(), nullable=True),
        sa.Column("redirect_uris", sa.JSON(), nullable=False),
        sa.Column("web_origins", sa.JSON(), nullable=False),
        sa.Column("standard_flow_enabled", sa.Boolean(), nullable=False),
        sa.Column("direct_access_grants_enabled", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["realm_id"], ["realms.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("realm_id", "client_id"),
    )
    with op.batch_alter_table("clients", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_clients_realm_id"), ["realm_id"], unique=False)

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("realm_id", sa.String(length=36), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("username_normalized", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("email_normalized", sa.String(length=320), nullable=True),
        sa.Column("email_verified", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["realm_id"], ["realms.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("realm_id", "email_normalized"),
        sa.UniqueConstraint("realm_id", "username_normalized"),
    )
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_users_realm_id"), ["realm_id"], unique=False)

    op.create_table(
        "credentials",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("secret_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "type"),
    )
    with op.batch_alter_table("credentials", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_credentials_user_id"), ["user_id"], unique=False)

    op.create_table(
        "authentication_sessions",
        sa.Column("tab_id", sa.String(length=128), nullable=False),
        sa.Column("realm_id", sa.String(length=36), nullable=False),
        sa.Column("client_id", sa.String(length=36), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column("current_execution", sa.String(length=128), nullable=False),
        sa.Column("selected_user_id", sa.String(length=36), nullable=True),
        sa.Column("auth_notes", sa.JSON(), nullable=False),
        sa.Column("password_update_allowed", sa.Boolean(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["clients.id"]),
        sa.ForeignKeyConstraint(["realm_id"], ["realms.id"]),
        sa.ForeignKeyConstraint(["selected_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("tab_id"),
    )
    with op.batch_alter_table("authentication_sessions", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_authentication_sessions_client_id"), ["client_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_authentication_sessions_realm_id"), ["realm_id"], unique=False
        )

    op.create_table(
        "reset_emails",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("realm_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("recipient", sa.String(length=320), nullable=False),
        sa.Column("action_token_hash", sa.String(length=64), nullable=False),
        sa.Column("consumed", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["realm_id"], ["realms.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("action_token_hash"),
    )
    with op.batch_alter_table("reset_emails", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_reset_emails_realm_id"), ["realm_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_reset_emails_user_id"), ["user_id"], unique=False)


def downgrade():
    with op.batch_alter_table("reset_emails", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_reset_emails_user_id"))
        batch_op.drop_index(batch_op.f("ix_reset_emails_realm_id"))

    op.drop_table("reset_emails")
    with op.batch_alter_table("authentication_sessions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_authentication_sessions_realm_id"))
        batch_op.drop_index(batch_op.f("ix_authentication_sessions_client_id"))

    op.drop_table("authentication_sessions")
    with op.batch_alter_table("credentials", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_credentials_user_id"))

    op.drop_table("credentials")
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_users_realm_id"))

    op.drop_table("users")
    with op.batch_alter_table("clients", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_clients_realm_id"))

    op.drop_table("clients")
    op.drop_table("realms")
