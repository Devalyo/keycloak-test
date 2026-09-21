"""Add user profile fields for realm imports.

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("first_name", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("last_name", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("attributes", sa.JSON(), nullable=False, server_default="{}"))


def downgrade():
    op.drop_column("users", "attributes")
    op.drop_column("users", "last_name")
    op.drop_column("users", "first_name")
