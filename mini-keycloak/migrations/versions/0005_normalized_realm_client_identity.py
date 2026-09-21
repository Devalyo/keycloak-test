"""Enforce normalized realm and client identities.

Revision ID: 0005
Revises: 0004

Backfill uses Python trim/casefold, not database lower(), which has different
Unicode semantics. Historical collisions abort before changing any schema/data;
operators must resolve those identities explicitly before retrying.
"""
from contextlib import contextmanager

from alembic import op
import sqlalchemy as sa


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


@contextmanager
def _schema_transaction():
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        # Prevent writes between collision detection and constraint creation.
        op.execute("LOCK TABLE realms, clients IN ACCESS EXCLUSIVE MODE")
        yield connection
        return

    # Alembic owns the transaction through its later alembic_version update.
    # sqlite3's legacy transaction mode has not emitted BEGIN for this revision
    # yet; start it explicitly so DDL and backfill share that commit/rollback.
    connection.exec_driver_sql("BEGIN IMMEDIATE")
    # These historical foreign keys use NO ACTION, so deferral permits batch
    # recreation without disabling enforcement or deleting dependent rows.
    # SQLite resets deferral on rollback, including any failed revision write.
    connection.exec_driver_sql("PRAGMA defer_foreign_keys=ON")
    yield connection
    if connection.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
        raise ValueError("Foreign key integrity check failed during identity migration")
    # DROP/recreate can leave SQLite's deferred-violation counter stale even
    # when the final graph is valid. Clear it only after checking every FK;
    # keep the writer lock and the original foreign_keys setting unchanged.
    connection.exec_driver_sql("PRAGMA defer_foreign_keys=OFF")


def upgrade():
    with _schema_transaction() as connection:
        realms = sa.table("realms", sa.column("id"), sa.column("name"),
                          sa.column("name_normalized", sa.String(765)))
        clients = sa.table("clients", sa.column("id"), sa.column("realm_id"),
                           sa.column("client_id"), sa.column("client_id_normalized", sa.String(765)))
        realm_rows = []
        client_rows = []
        names = set()
        for row in connection.execute(sa.select(realms.c.id, realms.c.name)):
            normalized = row.name.strip().casefold()
            if normalized in names:
                raise ValueError("Normalized identity collision in realms; resolve before migration")
            names.add(normalized)
            realm_rows.append({"row_id": row.id, "normalized": normalized})
        names = set()
        for row in connection.execute(sa.select(clients.c.id, clients.c.realm_id, clients.c.client_id)):
            normalized = row.client_id.strip().casefold()
            key = (row.realm_id, normalized)
            if key in names:
                raise ValueError("Normalized identity collision in clients; resolve before migration")
            names.add(key)
            client_rows.append({"row_id": row.id, "normalized": normalized})

        for table, column, rows, constraint, unique_fields in (
            (realms, "name_normalized", realm_rows, "uq_realms_name_normalized", ["name_normalized"]),
            (clients, "client_id_normalized", client_rows, "uq_clients_realm_client_id_normalized",
             ["realm_id", "client_id_normalized"]),
        ):
            op.add_column(table.name, sa.Column(column, sa.String(765), nullable=True))
            if rows:
                connection.execute(
                    table.update().where(table.c.id == sa.bindparam("row_id"))
                    .values({column: sa.bindparam("normalized")}), rows)
            with op.batch_alter_table(table.name) as batch:
                batch.alter_column(column, existing_type=sa.String(765), nullable=False)
                batch.create_unique_constraint(constraint, unique_fields)


def downgrade():
    with _schema_transaction():
        for table, column, constraint in (
            ("clients", "client_id_normalized", "uq_clients_realm_client_id_normalized"),
            ("realms", "name_normalized", "uq_realms_name_normalized"),
        ):
            with op.batch_alter_table(table) as batch:
                batch.drop_constraint(constraint, type_="unique")
                batch.drop_column(column)
