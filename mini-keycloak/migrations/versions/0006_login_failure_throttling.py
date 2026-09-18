"""Persist private, realm-scoped ordinary-login failure buckets.

Revision ID: 0006
Revises: 0005
"""
from alembic import op
import sqlalchemy as sa


revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def _begin_sqlite_transaction():
    connection = op.get_bind()
    if connection.dialect.name == 'sqlite':
        # sqlite3's legacy mode does not begin a transaction for DDL. Alembic
        # still owns the commit/rollback, including its later revision write.
        connection.exec_driver_sql('BEGIN IMMEDIATE')


def upgrade():
    _begin_sqlite_transaction()
    op.create_table('login_failure_buckets',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('realm_id', sa.String(36), sa.ForeignKey('realms.id'), nullable=False),
        sa.Column('bucket_hash', sa.String(64), nullable=False),
        sa.Column('failure_count', sa.Integer(), nullable=False),
        sa.Column('first_failure_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_failure_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('blocked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('realm_id', 'bucket_hash', name='uq_login_failure_buckets_realm_bucket'))
    op.create_index('ix_login_failure_buckets_realm_id', 'login_failure_buckets', ['realm_id'])
    op.create_index('ix_login_failure_buckets_expires_at', 'login_failure_buckets', ['expires_at'])


def downgrade():
    _begin_sqlite_transaction()
    op.drop_table('login_failure_buckets')
