"""Real data and deterministic transaction coordination for live tests."""

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import json
from queue import Queue
import secrets
import time

from sqlalchemy import MetaData, select, text
from sqlalchemy.orm import Session

from mini_keycloak.models import (AuthenticationSession, AuthorizationCode, Client,
    Credential, Realm, ResetEmail, SecurityEvent, User)
from mini_keycloak.models.identity import utc_now
from mini_keycloak.security.login_throttling import LoginThrottle
from mini_keycloak.security.passwords import PasswordService
from mini_keycloak.services.keys import RealmKeyService
from mini_keycloak.services.sessions import UserSessionService
from mini_keycloak.services.tokens import TokenService


@dataclass(frozen=True, repr=False)
class Graph:
    realm_id: str
    client_id: str
    user_id: str
    session_id: str
    sid: str
    code: str
    verifier: str
    refresh: str


def tokens(session, master):
    return TokenService(session, external_url="https://identity.example.test",
                        master_secret=master, access_seconds=300, refresh_seconds=600)


def seed_graph(session, master):
    realm = Realm(name="  Straße  ")
    session.add(realm)
    session.flush()
    client = Client(realm_id=realm.id, client_id="  Straße-ﬃ  ",
                    redirect_uris=["https://app.example.test/callback"])
    user = User(realm_id=realm.id, username="Alice", username_normalized="alice",
                email="alice@example.test", email_normalized="alice@example.test")
    session.add_all([client, user])
    session.flush()
    session.add(Credential(user_id=user.id, secret_hash=PasswordService().hash(secrets.token_urlsafe(24))))
    RealmKeyService(session, master).ensure_active_key(realm.id)
    user_session = UserSessionService(session, idle_seconds=600, max_seconds=1200).create(realm, client, user)
    code, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    common = dict(realm_id=realm.id, client_id=client.id, user_id=user.id,
                  user_session_id=user_session.id)
    session.add(AuthorizationCode(**common, code_hash=hashlib.sha256(code.encode()).hexdigest(),
        redirect_uri=client.redirect_uris[0], scope="openid", code_challenge=challenge,
        code_challenge_method="S256", expires_at=utc_now() + timedelta(minutes=5)))
    session.add(SecurityEvent(**common, event_type="LOGIN"))
    session.add(AuthenticationSession(tab_id=secrets.token_urlsafe(32), realm_id=realm.id,
        client_id=client.id, selected_user_id=user.id, current_execution="authenticated",
        redirect_uri=client.redirect_uris[0], expires_at=utc_now() + timedelta(minutes=5)))
    # Stored historical data only: this fixture does not invoke the reset flow.
    session.add(ResetEmail(realm_id=realm.id, user_id=user.id, recipient=user.email,
        action_token_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        expires_at=utc_now() + timedelta(minutes=5)))
    LoginThrottle(session, secret=master, threshold=100, window_seconds=300,
                  lock_seconds=60).record_failure(realm.id, "a" * 64)
    issued = tokens(session, master).issue(realm=realm, client=client,
        user_session=user_session, scope="openid")
    graph = Graph(realm.id, client.id, user.id, user_session.id, user_session.sid,
                  code, verifier, issued["refresh_token"])
    session.commit()
    return graph


def snapshot(engine, *, omit_tables=(), omit_columns=()):
    """Compare complete persisted values without exposing keys in failure diffs."""
    metadata = MetaData()
    metadata.reflect(bind=engine)
    result = {}
    with engine.connect() as connection:
        for table in metadata.sorted_tables:
            if table.name in omit_tables:
                continue
            columns = [column for column in table.c if column.name not in omit_columns]
            rows = connection.execute(select(*columns).order_by(*table.primary_key.columns)).all()
            payload = json.dumps([list(row) for row in rows], default=str, sort_keys=True)
            result[table.name] = (len(rows), hashlib.sha256(payload.encode()).hexdigest())
    return result


def locked_pair(engine, first, second, *, rollback=False):
    """Observe the second backend waiting on the first, then release its lock.

    No scheduling sleeps or simulated database calls. Statement/lock timeouts
    on every test connection bound failures and the first always rolls back
    if the observer or worker fails.
    """
    pids = Queue()

    def worker():
        with Session(engine) as session:
            pids.put(session.scalar(text("SELECT pg_backend_pid()")))
            result = second(session)
            session.commit()
            return result

    with ThreadPoolExecutor(max_workers=1) as executor, Session(engine) as session:
        owner = session.scalar(text("SELECT pg_backend_pid()"))
        first_result = first(session)
        future = executor.submit(worker)
        try:
            waiter = pids.get(timeout=5)
            deadline = time.monotonic() + 5
            with engine.connect() as observer:
                while True:
                    blocking = observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": waiter})
                    if owner in blocking:
                        break
                    if future.done():
                        future.result()  # Propagate a real operation failure.
                        raise AssertionError("Second transaction did not contend on the first")
                    assert time.monotonic() < deadline, "Expected database lock was not observed"
            session.rollback() if rollback else session.commit()
            return first_result, future.result(timeout=15)
        finally:
            session.rollback()
