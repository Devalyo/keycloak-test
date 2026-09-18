from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from mini_keycloak.models import Realm, RealmKey


class RealmKeyRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def lock_realm(self, realm_id: str) -> bool:
        if self.session.get_bind().dialect.name == "sqlite":
            # SQLite ignores FOR UPDATE. A no-op write acquires its writer lock
            # before the existence check and holds it until the caller commits.
            self.session.execute(
                update(Realm).where(Realm.id == realm_id).values(id=Realm.id)
            )
        return self.session.execute(
            select(Realm.enabled).where(Realm.id == realm_id).with_for_update()
        ).scalar_one()

    def realm_enabled(self, realm_id: str) -> bool:
        return self.session.scalar(select(Realm.enabled).where(Realm.id == realm_id)) is True

    def get_active(self, realm_id: str) -> RealmKey | None:
        return self.session.execute(
            select(RealmKey).where(
                RealmKey.realm_id == realm_id,
                RealmKey.active.is_(True),
                RealmKey.algorithm == "RS256",
            )
        ).scalar_one_or_none()

    def list_verification_keys(self, realm_id: str) -> list[RealmKey]:
        return list(self.session.scalars(
            select(RealmKey).where(
                RealmKey.realm_id == realm_id,
                RealmKey.algorithm == "RS256",
            ).order_by(RealmKey.created_at, RealmKey.id)
        ))

    def add(self, key: RealmKey) -> RealmKey:
        self.session.add(key)
        self.session.flush()
        return key

    def deactivate_active(self, realm_id: str, deactivated_at: datetime) -> None:
        self.session.execute(
            update(RealmKey).where(
                RealmKey.realm_id == realm_id,
                RealmKey.algorithm == "RS256",
                RealmKey.active.is_(True),
            ).values(active=False, deactivated_at=deactivated_at)
        )
