"""Persist realm authentication flows and reset-message metadata.

Revision ID: 0007
Revises: 0006
"""
from contextlib import contextmanager
from uuid import uuid4

from alembic import op
import sqlalchemy as sa


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

PROVIDERS = (
    ("choose-user", "reset-credentials-choose-user"),
    ("email-gate", "reset-credential-email"),
    ("update-password", "reset-password"),
)
CURRENT_EXECUTION_NOTE = "current.authentication.execution"


@contextmanager
def _schema_transaction():
    connection = op.get_bind()
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
    else:
        connection.exec_driver_sql("LOCK TABLE realms, authentication_sessions, reset_emails IN ACCESS EXCLUSIVE MODE")
    yield connection
    if connection.dialect.name == "sqlite":
        if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
            raise ValueError("Foreign key integrity check failed during authentication flow migration")
        connection.exec_driver_sql("PRAGMA defer_foreign_keys=OFF")


def upgrade():
    with _schema_transaction() as connection:
        op.create_table("authentication_flows",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("realm_id", sa.String(36), sa.ForeignKey("realms.id"), nullable=False),
            sa.Column("alias", sa.String(255), nullable=False),
            sa.Column("provider_id", sa.String(64), nullable=False),
            sa.Column("built_in", sa.Boolean(), nullable=False),
            sa.UniqueConstraint("realm_id", "alias", name="uq_authentication_flows_realm_alias"))
        op.create_index("ix_authentication_flows_realm_id", "authentication_flows", ["realm_id"])
        op.create_table("authentication_executions",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("flow_id", sa.String(36), sa.ForeignKey("authentication_flows.id"), nullable=False),
            sa.Column("authenticator", sa.String(128), nullable=False),
            sa.Column("requirement", sa.String(32), nullable=False),
            sa.Column("priority", sa.Integer(), nullable=False))
        op.create_index("ix_authentication_executions_flow_id", "authentication_executions", ["flow_id"])
        with op.batch_alter_table("realms") as batch:
            batch.add_column(sa.Column("reset_credentials_flow_id", sa.String(36), nullable=True))
            batch.create_foreign_key("fk_realms_reset_credentials_flow_id", "authentication_flows",
                                     ["reset_credentials_flow_id"], ["id"], ondelete="SET NULL")
        with op.batch_alter_table("authentication_sessions") as batch:
            batch.add_column(sa.Column("flow_id", sa.String(36), nullable=True))
            batch.add_column(sa.Column("execution_status", sa.JSON(), nullable=False, server_default="{}"))
            batch.create_foreign_key("fk_authentication_sessions_flow_id", "authentication_flows", ["flow_id"], ["id"])
            batch.create_index("ix_authentication_sessions_flow_id", ["flow_id"])
        with op.batch_alter_table("reset_emails") as batch:
            batch.add_column(sa.Column("client_id", sa.String(36), nullable=True))
            batch.add_column(sa.Column("authentication_session_id", sa.String(128), nullable=True))
            batch.add_column(sa.Column("token_id", sa.String(128), nullable=True))
            batch.add_column(sa.Column("action_token", sa.Text(), nullable=True))
            batch.add_column(sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True))
            batch.create_foreign_key("fk_reset_emails_client_id", "clients", ["client_id"], ["id"])
            batch.create_foreign_key("fk_reset_emails_authentication_session_id", "authentication_sessions",
                                     ["authentication_session_id"], ["tab_id"])
            batch.create_unique_constraint("uq_reset_emails_token_id", ["token_id"])
            batch.create_index("ix_reset_emails_client_id", ["client_id"])
            batch.create_index("ix_reset_emails_authentication_session_id", ["authentication_session_id"])

        metadata = sa.MetaData()
        metadata.reflect(connection, only=["realms", "authentication_flows", "authentication_executions", "authentication_sessions"])
        realms, flows, executions, sessions = (metadata.tables[name] for name in (
            "realms", "authentication_flows", "authentication_executions", "authentication_sessions"))
        for realm_id in connection.scalars(sa.select(realms.c.id)).all():
            flow_id = str(uuid4())
            connection.execute(flows.insert().values(id=flow_id, realm_id=realm_id,
                alias="reset credentials", provider_id="basic-flow", built_in=True))
            execution_ids = [str(uuid4()) for _ in PROVIDERS]
            for index, (_, provider) in enumerate(PROVIDERS):
                connection.execute(executions.insert().values(id=execution_ids[index], flow_id=flow_id,
                    authenticator=provider, requirement="REQUIRED", priority=(index + 1) * 10))
            connection.execute(realms.update().where(realms.c.id == realm_id).values(reset_credentials_flow_id=flow_id))
            for session in connection.execute(sa.select(sessions).where(sessions.c.realm_id == realm_id)).mappings().all():
                values = {"flow_id": flow_id}
                for index, (semantic, _) in enumerate(PROVIDERS):
                    if session["current_execution"] == semantic:
                        notes = dict(session["auth_notes"])
                        if semantic == "update-password":
                            # Pending credentials resume through fresh message delivery.
                            index = 1 if session["selected_user_id"] is not None else 0
                            notes.pop("auth.selector.screen.rendered", None)
                            values["password_update_allowed"] = False
                        notes[CURRENT_EXECUTION_NOTE] = execution_ids[index]
                        values.update(current_execution=execution_ids[index], auth_notes=notes,
                            execution_status={**{identifier: "SUCCESS" for identifier in execution_ids[:index]},
                                              execution_ids[index]: "CHALLENGED"})
                        break
                connection.execute(sessions.update().where(sessions.c.tab_id == session["tab_id"]).values(**values))


def downgrade():
    with _schema_transaction() as connection:
        metadata = sa.MetaData()
        metadata.reflect(connection, only=["authentication_sessions", "authentication_executions"])
        sessions = metadata.tables["authentication_sessions"]
        executions = metadata.tables["authentication_executions"]
        semantics = dict((provider, semantic) for semantic, provider in PROVIDERS)
        execution_map = {row.id: semantics.get(row.authenticator)
                         for row in connection.execute(sa.select(executions))}
        for session in connection.execute(sa.select(sessions)).mappings().all():
            notes = dict(session["auth_notes"])
            current = notes.pop(CURRENT_EXECUTION_NOTE, session["current_execution"])
            semantic = None if session["current_execution"] == "authenticated" else execution_map.get(current)
            values = {"auth_notes": notes}
            if semantic is not None:
                values["current_execution"] = semantic
            connection.execute(sessions.update().where(sessions.c.tab_id == session["tab_id"]).values(**values))
        with op.batch_alter_table("reset_emails") as batch:
            batch.drop_index("ix_reset_emails_client_id")
            batch.drop_index("ix_reset_emails_authentication_session_id")
            batch.drop_constraint("fk_reset_emails_client_id", type_="foreignkey")
            batch.drop_constraint("fk_reset_emails_authentication_session_id", type_="foreignkey")
            batch.drop_constraint("uq_reset_emails_token_id", type_="unique")
            for column in ("client_id", "authentication_session_id", "token_id", "action_token", "consumed_at"):
                batch.drop_column(column)
        with op.batch_alter_table("authentication_sessions") as batch:
            batch.drop_index("ix_authentication_sessions_flow_id")
            batch.drop_constraint("fk_authentication_sessions_flow_id", type_="foreignkey")
            batch.drop_column("flow_id")
            batch.drop_column("execution_status")
        with op.batch_alter_table("realms") as batch:
            batch.drop_constraint("fk_realms_reset_credentials_flow_id", type_="foreignkey")
            batch.drop_column("reset_credentials_flow_id")
        op.drop_table("authentication_executions")
        op.drop_table("authentication_flows")
