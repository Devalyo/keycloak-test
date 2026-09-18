"""Contention through real independent PostgreSQL transactions."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta
from threading import Barrier

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mini_keycloak.extensions import db
from mini_keycloak.import_export.validation import validate_realm_import
from mini_keycloak.models import (AuthenticationSession, AuthorizationCode, Client, Credential, LoginFailureBucket,
    Realm, RealmKey, RefreshToken, ResetEmail, SecurityEvent, User, UserSession)
from mini_keycloak.models.identity import utc_now
from mini_keycloak.oidc.errors import InvalidGrant, RefreshReuse
from mini_keycloak.security.login_throttling import LoginThrottle
from mini_keycloak.services.authorization import AuthorizationService
from mini_keycloak.services.action_tokens import ResetActionTokenService
from mini_keycloak.services.authentication_flows import AuthenticationFlowService
from mini_keycloak.services.keys import RealmKeyService
from mini_keycloak.services.realm_import import RealmImportError, RealmImportService
from mini_keycloak.services.sessions import revoke_session
from .support import locked_pair, seed_graph, tokens


pytestmark = pytest.mark.postgres


@pytest.fixture
def graph(postgres_app, postgres_database):
    with postgres_app.app_context():
        return seed_graph(db.session, postgres_database.master)


@pytest.mark.parametrize('rollback', [False, True])
def test_reset_token_consumption_has_one_winner_and_releases_rolled_back_claim(
        postgres_app, postgres_database, graph, rollback, caplog):
    with postgres_app.app_context():
        engine = db.engine
        realm = db.session.get(Realm, graph.realm_id)
        user = db.session.get(User, graph.user_id)
        flow_service = AuthenticationFlowService(db.session)
        flow = flow_service.ensure_reset_flow(realm)
        execution = next(item for item in flow_service.executions(flow.id)
                         if item.authenticator == 'reset-credentials-choose-user')
        auth = AuthenticationSession(tab_id='reset-consumption', realm_id=realm.id,
            client_id=graph.client_id, selected_user_id=user.id, flow_id=flow.id,
            current_execution=execution.id, redirect_uri='https://app.example.test/callback',
            expires_at=utc_now() + timedelta(minutes=5))
        db.session.add(auth)
        db.session.flush()
        message = ResetActionTokenService(db.session, secret=postgres_database.secret).issue(auth, user)
        message_id, raw, realm_name = message.id, message.action_token, realm.name
        db.session.commit()
        db.session.remove()

        def consume(session):
            try:
                selected_auth, selected_user = ResetActionTokenService(
                    session, secret=postgres_database.secret).consume(realm_name, raw)
                assert selected_auth.tab_id == 'reset-consumption'
                assert selected_user.id == graph.user_id
                return 'ok'
            except ValueError as error:
                assert str(error) == 'Invalid action token'
                session.rollback()
                return 'invalid'

        first, second = locked_pair(engine, consume, consume, rollback=rollback)
        assert first == 'ok' and second == ('ok' if rollback else 'invalid')
        with Session(engine) as session:
            stored = session.get(ResetEmail, message_id)
            assert stored.consumed and stored.consumed_at is not None
            assert session.scalar(select(func.count()).select_from(ResetEmail).where(
                ResetEmail.authentication_session_id == 'reset-consumption')) == 1
            assert consume(session) == 'invalid'
            assert session.is_active and not session.in_transaction()
        assert raw not in caplog.text


@pytest.mark.parametrize("entity", ["realm", "client"])
def test_casefold_import_has_one_winner_and_no_partial_loser(
        postgres_app, postgres_database, monkeypatch, entity, caplog):
    master = postgres_database.master
    with postgres_app.app_context():
        engine = db.engine
        if entity == "client":
            RealmImportService(db.session, master).import_realm(validate_realm_import({"realm": "Tenant"}).value)
            db.session.commit()
        barrier = Barrier(2, timeout=10)
        preflight = RealmImportService._preflight

        def synchronized(self, *args, **kwargs):
            result = preflight(self, *args, **kwargs)
            barrier.wait()
            return result

        def import_one(index):
            name = (("Concurrent", "CONCURRENT") if entity == "realm" else ("Straße", "STRASSE"))[index]
            value = validate_realm_import({
                "realm": name if entity == "realm" else "Tenant",
                "displayName": f"winner-{index}",
                "clients": [{"clientId": name if entity == "client" else f"client-{index}"}],
                "users": [{"username": f"user-{index}", "credentials": [
                    {"type": "password", "value": master}]}],
            }, update=entity == "client").value
            with Session(engine) as session:
                try:
                    RealmImportService(session, master).import_realm(value, update=entity == "client")
                    session.commit()
                    return "won", index
                except RealmImportError as error:
                    assert str(error) == "Realm import failed"
                    assert error.__cause__ is None and error.__context__ is None
                    assert session.is_active and not session.in_transaction()
                    return "lost", index

        with monkeypatch.context() as patch:
            patch.setattr(RealmImportService, "_preflight", synchronized)
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(import_one, range(2)))
        assert sorted(outcome for outcome, index in results) == ["lost", "won"]
        winner = next(index for outcome, index in results if outcome == "won")
        with Session(engine) as session:
            for model in (Realm, Client, User, Credential, RealmKey):
                assert session.scalar(select(func.count()).select_from(model)) == 1
            realm = session.scalars(select(Realm)).one()
            assert realm.display_name == f"winner-{winner}"
            assert session.scalar(select(User.username)) == f"user-{winner}"
            assert session.scalar(select(Client.client_id_normalized)) == ("strasse" if entity == "client" else f"client-{winner}")
            # A later update in a new transaction succeeds after loser rollback.
            update = validate_realm_import({"realm": realm.name, "displayName": "retry"}, update=True).value
            RealmImportService(session, master).import_realm(update, update=True)
            session.commit()
            assert session.scalar(select(Realm.display_name)) == "retry"
        assert not any(value in caplog.text for value in (master, postgres_database.url))


@pytest.mark.parametrize("rollback", [False, True])
def test_code_consumption_contends_and_rollback_releases_claim(
        postgres_app, postgres_database, graph, rollback):
    with postgres_app.app_context():
        engine = db.engine

        def exchange(session):
            session.add(SecurityEvent(realm_id=graph.realm_id, client_id=graph.client_id,
                user_id=graph.user_id, user_session_id=graph.session_id, event_type="CODE_TO_TOKEN"))
            try:
                AuthorizationService(session, lifetime_seconds=60).consume(graph.code,
                    realm_id=graph.realm_id, client_id=graph.client_id,
                    redirect_uri="https://app.example.test/callback", code_verifier=graph.verifier)
                tokens(session, postgres_database.master).issue(realm=session.get(Realm, graph.realm_id),
                    client=session.get(Client, graph.client_id), user_session=session.get(UserSession, graph.session_id),
                    scope="openid")
                return "ok"
            except InvalidGrant:
                assert not session.in_transaction()
                return "invalid"

        first, second = locked_pair(engine, exchange, exchange, rollback=rollback)
        assert first == "ok" and second == ("ok" if rollback else "invalid")
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(AuthorizationCode)) == 1
            assert session.scalar(select(AuthorizationCode.consumed_at)) is not None
            assert session.scalar(select(func.count()).select_from(RefreshToken)) == 2
            assert session.scalar(select(func.count()).select_from(SecurityEvent).where(
                SecurityEvent.event_type == "CODE_TO_TOKEN")) == 1
            assert exchange(session) == "invalid"


@dataclass(frozen=True, repr=False)
class RefreshResult:
    outcome: str
    raw: str | None = None


def refresh_operation(graph, master, raw):
    def refresh(session):
        try:
            result = tokens(session, master).refresh(raw, realm=session.get(Realm, graph.realm_id),
                client=session.get(Client, graph.client_id), idle_seconds=600)
            return RefreshResult("ok", result["refresh_token"])
        except RefreshReuse:
            # Match the endpoint transaction boundary: defensive revocation
            # must be committed even though the caller receives invalid_grant.
            return RefreshResult("reuse")
        except InvalidGrant:
            session.rollback()
            return RefreshResult("invalid")
    return refresh


def assert_revoked(engine, graph, *, generations):
    with Session(engine) as session:
        rows = session.scalars(select(RefreshToken).where(RefreshToken.user_session_id == graph.session_id)
                               .order_by(RefreshToken.generation)).all()
        assert [row.generation for row in rows] == generations
        assert all(row.revoked_at is not None for row in rows)
        assert session.get(UserSession, graph.session_id).revoked_at is not None


def test_refresh_one_winner_commits_reuse_family_revocation(postgres_app, postgres_database, graph):
    with postgres_app.app_context():
        engine = db.engine
        refresh = refresh_operation(graph, postgres_database.master, graph.refresh)
        first, second = locked_pair(engine, refresh, refresh)
        assert (first.outcome, second.outcome) == ("ok", "reuse")
        assert_revoked(engine, graph, generations=[0, 1])
        with Session(engine) as session:
            assert refresh_operation(graph, postgres_database.master, first.raw)(session).outcome == "invalid"
            assert session.scalar(select(func.count()).select_from(SecurityEvent).where(
                SecurityEvent.event_type == "REFRESH_TOKEN_REUSE")) == 1


def test_refresh_rollback_leaves_no_child_and_allows_retry(postgres_app, postgres_database, graph):
    with postgres_app.app_context():
        engine = db.engine
        refresh = refresh_operation(graph, postgres_database.master, graph.refresh)
        first, second = locked_pair(engine, refresh, refresh, rollback=True)
        assert (first.outcome, second.outcome) == ("ok", "ok")
        with Session(engine) as session:
            rows = session.scalars(select(RefreshToken).order_by(RefreshToken.generation)).all()
            assert [row.generation for row in rows] == [0, 1]
            assert all(row.revoked_at is None for row in rows)
            assert rows[0].used_at is not None and rows[0].replaced_by_id == rows[1].id
            assert refresh_operation(graph, postgres_database.master, first.raw)(session).outcome == "invalid"
            assert refresh_operation(graph, postgres_database.master, second.raw)(session).outcome == "ok"
            session.commit()


@pytest.mark.parametrize("reuse_first", [False, True])
def test_ancestor_reuse_racing_descendant_cannot_leave_live_descendant(
        postgres_app, postgres_database, graph, reuse_first):
    with postgres_app.app_context():
        engine = db.engine
        ancestor = refresh_operation(graph, postgres_database.master, graph.refresh)
        with Session(engine) as session:
            child = ancestor(session)
            session.commit()
        assert child.outcome == "ok"
        descendant = refresh_operation(graph, postgres_database.master, child.raw)
        operations = (ancestor, descendant) if reuse_first else (descendant, ancestor)
        first, second = locked_pair(engine, *operations)
        assert (first.outcome, second.outcome) == (("reuse", "invalid") if reuse_first else ("ok", "reuse"))
        assert_revoked(engine, graph, generations=[0, 1] if reuse_first else [0, 1, 2])


@pytest.mark.parametrize("logout_first", [False, True])
def test_logout_racing_refresh_revokes_every_descendant(postgres_app, postgres_database, graph, logout_first):
    with postgres_app.app_context():
        engine = db.engine

        def logout(session):
            assert revoke_session(session, graph.sid, graph.realm_id)
            return RefreshResult("logout")

        refresh = refresh_operation(graph, postgres_database.master, graph.refresh)
        operations = (logout, refresh) if logout_first else (refresh, logout)
        first, second = locked_pair(engine, *operations)
        assert (first.outcome, second.outcome) == (("logout", "invalid") if logout_first else ("ok", "logout"))
        assert_revoked(engine, graph, generations=[0] if logout_first else [0, 1])


@pytest.mark.parametrize("rollback", [False, True])
def test_signing_key_rotation_serializes_and_rollback_releases_realm(
        postgres_app, postgres_database, graph, rollback):
    with postgres_app.app_context():
        engine = db.engine

        def rotate(session):
            return RealmKeyService(session, postgres_database.master).rotate_active_key(graph.realm_id).kid

        first, second = locked_pair(engine, rotate, rotate, rollback=rollback)
        with Session(engine) as session:
            keys = session.scalars(select(RealmKey)).all()
            assert len(keys) == (2 if rollback else 3)
            assert [key.kid for key in keys if key.active] == [second]
            assert sum(key.kid == first for key in keys) == (0 if rollback else 1)
            # Tokens issued under the retained original key remain verifiable.
            claims = tokens(session, postgres_database.master).verify(graph.refresh,
                realm=session.get(Realm, graph.realm_id), audience="  Straße-ﬃ  ", token_type="Refresh")
            assert claims["sid"] == graph.sid


def test_atomic_throttle_upserts_do_not_lose_concurrent_failures(postgres_app, postgres_database, graph):
    with postgres_app.app_context():
        engine = db.engine
        barrier = Barrier(8, timeout=10)
        now = utc_now()

        def fail(index):
            with Session(engine) as session:
                # Check out independent connections before releasing workers.
                session.connection()
                limiter = LoginThrottle(session, secret=postgres_database.secret,
                    threshold=100, window_seconds=300, lock_seconds=60)
                barrier.wait()
                for attempt in range(5):
                    limiter.record_failure(graph.realm_id, "b" * 64, now=now)
                session.commit()

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(fail, range(8)))
        with Session(engine) as session:
            bucket = session.scalars(select(LoginFailureBucket).where(LoginFailureBucket.bucket_hash == "b" * 64)).one()
            assert bucket.failure_count == 40
            assert bucket.blocked_until is None
            assert bucket.first_failure_at == bucket.last_failure_at == now
            assert session.scalar(select(LoginFailureBucket.failure_count).where(
                LoginFailureBucket.bucket_hash == "a" * 64)) == 1
