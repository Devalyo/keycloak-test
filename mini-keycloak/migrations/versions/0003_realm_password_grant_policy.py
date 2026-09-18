"""Require explicit realm policy for direct password grants.

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('realms', sa.Column('password_grant_enabled', sa.Boolean(),
                                    nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column('realms', 'password_grant_enabled')
