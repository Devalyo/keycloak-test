"""Persist authentication-session continuation state.

Revision ID: 0008
Revises: 0007
"""
import hashlib
from uuid import uuid4

from alembic import op
import sqlalchemy as sa


revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("authentication_sessions") as batch:
        batch.add_column(sa.Column("session_code_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column(
            "browser_binding_generation", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column(
            "required_actions", sa.JSON(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("current_required_action", sa.String(128), nullable=True))

    connection = op.get_bind()
    sessions = sa.table(
        "authentication_sessions",
        sa.column("tab_id", sa.String(128)),
        sa.column("session_code_hash", sa.String(64)),
    )
    for tab_id in connection.scalars(sa.select(sessions.c.tab_id)).all():
        digest = hashlib.sha256(uuid4().bytes).hexdigest()
        connection.execute(sessions.update().where(
            sessions.c.tab_id == tab_id).values(session_code_hash=digest))

    with op.batch_alter_table("authentication_sessions") as batch:
        batch.alter_column("session_code_hash", existing_type=sa.String(64), nullable=False)


def downgrade():
    with op.batch_alter_table("authentication_sessions") as batch:
        batch.drop_column("current_required_action")
        batch.drop_column("required_actions")
        batch.drop_column("browser_binding_generation")
        batch.drop_column("session_code_hash")
