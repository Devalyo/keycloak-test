"""Add realm mail settings.

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import sqlalchemy as sa


revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("realms", sa.Column("smtp_server", sa.JSON(), nullable=False,
                                      server_default="{}"))


def downgrade():
    op.drop_column("realms", "smtp_server")
