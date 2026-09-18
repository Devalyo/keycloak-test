from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, timezone
import hashlib
from threading import Barrier

import jwt
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from mini_keycloak.extensions import db
from mini_keycloak.models import AuthenticationSession, ResetEmail
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.services.action_tokens import ResetActionTokenService
from mini_keycloak.services.authentication_flows import AuthenticationFlowService


SECRET = "reset-service-test-key-with-at-least-48-bytes-for-tests"


@pytest.fixture
def reset(db_app):
    with db_app.app_context():
        identities = IdentityRepository(db.session)
        realm = identities.create_realm("reset-realm")
        client = identities.create_client(realm.id, "reset-client", redirect_uris=["https://client.test/callback"])
        user = identities.create_user(realm.id, "reset-user", "reset@example.test", "OriginalPassw0rd!")
        flow = AuthenticationFlowService(db.session).ensure_reset_flow(realm)
        repository = AuthenticationRepository(db.session)
        executions = repository.executions(flow.id)
        auth = repository.create_session(realm, client, client.redirect_uris[0], executions[0].id)
        auth.flow_id = flow.id
        auth.selected_user_id = user.id
        db.session.commit()
        yield realm, client, user, auth, executions


def service(session=None):
    return ResetActionTokenService(session if session is not None else db.session, secret=SECRET)


def test_issue_signed_message_with_complete_associations_and_private_cli(reset, db_app):
    realm, client, user, auth, _ = reset
    message = service().issue(auth, user)
    db.session.commit()
    claims = jwt.decode(message.action_token, SECRET, algorithms=["HS256"])
    assert set(claims) == {"typ", "jti", "sub", "realm_id", "client_id", "asid", "iat", "exp"}
    assert claims == dict(typ="reset-credentials", jti=message.token_id, sub=user.id,
                         realm_id=realm.id, client_id=client.id, asid=auth.tab_id,
                         iat=int(message.created_at.replace(tzinfo=timezone.utc).timestamp()),
                         exp=int(message.expires_at.replace(tzinfo=timezone.utc).timestamp()))
    assert message.recipient == user.email
    assert (message.realm_id, message.client_id, message.user_id, message.authentication_session_id) == (
        realm.id, client.id, user.id, auth.tab_id)
    assert message.action_token_hash == hashlib.sha256(message.action_token.encode()).hexdigest()
    assert message.consumed_at is None and not message.consumed
    assert db.session.scalar(select(func.count(ResetEmail.id))) == 1
    result = db_app.test_cli_runner().invoke(args=["outbox-list"])
    assert result.exit_code == 0 and user.email in result.output
    assert message.action_token not in result.output
    assert message.action_token_hash not in result.output


def test_consume_returns_same_session_and_user_and_is_single_use(reset):
    realm, _, user, auth, _ = reset
    message = service().issue(auth, user)
    raw = message.action_token
    db.session.commit()
    assert service().consume(realm.name, raw) == (auth, user)
    db.session.commit()
    assert message.consumed_at is not None and message.consumed
    with pytest.raises(ValueError, match="^Invalid action token$"):
        service().consume(realm.name, raw)


@pytest.mark.parametrize("change", [
    "signature", "algorithm", "malformed", "realm", "typ", "jti", "sub", "realm_id",
    "client_id", "asid", "missing", "extra", "string_iat", "bool_exp", "future_iat",
    "expired", "digest", "row_expired", "session_expired", "disabled_user", "disabled_client",
    "disabled_realm", "selected_user", "client_realm", "user_realm", "flow", "row_client",
    "row_user", "row_session", "row_time",
])
def test_rejected_tokens_leave_message_unconsumed(reset, change):
    realm, client, user, auth, _ = reset
    message = service().issue(auth, user)
    raw = message.action_token
    claims = jwt.decode(raw, SECRET, algorithms=["HS256"])
    name = realm.name
    if change in {"typ", "jti", "sub", "realm_id", "client_id", "asid"}:
        claims[change] = "different"
    elif change == "missing":
        del claims["iat"]
    elif change == "extra":
        claims["unexpected"] = "value"
    elif change == "string_iat":
        claims["iat"] = str(claims["iat"])
    elif change == "bool_exp":
        claims["exp"] = True
    elif change == "future_iat":
        claims["iat"] += 3600
    elif change == "expired":
        claims["exp"] = int((utc_now() - timedelta(seconds=1)).timestamp())
    raw = jwt.encode(claims, SECRET, algorithm="HS256")
    # Persist the candidate digest so relationship and claim validation are independent.
    message.action_token_hash = hashlib.sha256(raw.encode()).hexdigest()
    if change == "signature":
        raw = jwt.encode(claims, "another-signing-key-with-at-least-32-bytes", algorithm="HS256")
    elif change == "algorithm":
        raw = jwt.encode(claims, SECRET, algorithm="HS384")
    elif change == "malformed":
        raw = "invalid-token"
    elif change == "realm":
        name = "different-realm"
    elif change == "digest":
        message.action_token_hash = "0" * 64
    elif change == "row_expired":
        message.expires_at = utc_now() - timedelta(seconds=1)
    elif change == "session_expired":
        auth.expires_at = utc_now() - timedelta(seconds=1)
    elif change.startswith("disabled_"):
        {"disabled_user": user, "disabled_client": client, "disabled_realm": realm}[change].enabled = False
    elif change == "selected_user":
        auth.selected_user_id = None
    elif change == "flow":
        auth.flow_id = None
    elif change == "row_time":
        message.created_at = utc_now() - timedelta(days=1)
    elif change in {"client_realm", "user_realm"}:
        other = IdentityRepository(db.session).create_realm("other")
        (client if change == "client_realm" else user).realm_id = other.id
    elif change in {"row_client", "row_user", "row_session"}:
        setattr(message, {"row_client": "client_id", "row_user": "user_id", "row_session": "authentication_session_id"}[change], None if change != "row_user" else "different")
        # These in-memory associations are validated before any caller flush.
    if change not in {"row_client", "row_user", "row_session"}:
        db.session.commit()
    with db.session.no_autoflush:
        with pytest.raises(ValueError, match="^Invalid action token$"):
            service().consume(name, raw)
    assert message.consumed_at is None and not message.consumed


@pytest.mark.parametrize("change", ["disabled", "email", "selected_user", "expired", "client_disabled"])
def test_issue_rejects_ineligible_relationships(reset, change):
    _, client, user, auth, _ = reset
    if change == "disabled":
        user.enabled = False
    elif change == "email":
        user.email = None
    elif change == "selected_user":
        auth.selected_user_id = None
    elif change == "expired":
        auth.expires_at = utc_now() - timedelta(seconds=1)
    else:
        client.enabled = False
    with pytest.raises(ValueError, match="^Invalid action token$"):
        service().issue(auth, user)
    assert db.session.scalar(select(func.count(ResetEmail.id))) == 0


def test_issue_and_consumption_preserve_caller_transaction(reset):
    realm, _, user, auth, _ = reset
    message = service().issue(auth, user)
    db.session.rollback()
    assert db.session.scalar(select(func.count(ResetEmail.id))) == 0
    message = service().issue(auth, user)
    raw, message_id = message.action_token, message.id
    db.session.commit()
    service().consume(realm.name, raw)
    db.session.rollback()
    persisted = db.session.get(ResetEmail, message_id)
    assert persisted.consumed_at is None and not persisted.consumed
    assert service().consume(realm.name, raw) == (auth, user)


def test_concurrent_consumers_have_one_winner(reset):
    realm, _, user, auth, _ = reset
    message = service().issue(auth, user)
    raw, name, message_id = message.action_token, realm.name, message.id
    db.session.commit()
    factory = sessionmaker(bind=db.engine, expire_on_commit=False)
    barrier = Barrier(2)

    def consume():
        with factory() as session:
            # Both transactions observe the same initially available message.
            assert session.get(ResetEmail, message_id).consumed_at is None
            barrier.wait(timeout=5)
            try:
                service(session).consume(name, raw)
                session.commit()
                return "accepted"
            except ValueError:
                session.rollback()
                return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: consume(), range(2)))
    assert sorted(outcomes) == ["accepted", "rejected"]
    db.session.expire_all()
    assert db.session.get(ResetEmail, message_id).consumed_at is not None


@pytest.fixture
def authenticators(reset):
    from mini_keycloak.authentication import AuthenticationProcessor, AuthenticatorRegistry
    from mini_keycloak.reset_credentials.authenticators import (
        ResetCredentialChooseUser, ResetCredentialEmail, ResetPassword,
    )
    realm, client, user, auth, executions = reset
    auth.selected_user_id = None
    registry = AuthenticatorRegistry(dict(zip(
        (execution.authenticator for execution in executions),
        (ResetCredentialChooseUser(), ResetCredentialEmail(service()), ResetPassword()),
    )))
    return AuthenticationProcessor(db.session, realm_name=realm.name, client_id=client.client_id,
                                   tab_id=auth.tab_id, registry=registry)


def continue_token(reset, processor):
    from mini_keycloak.reset_credentials.authenticators import ACTION_TOKEN_USER_ID
    realm, _, user, auth, executions = reset
    processor.process_flow()
    processor.process_action(executions[0].id, {"username": user.username})
    message = db.session.scalar(select(ResetEmail))
    service().consume(realm.name, message.action_token)
    auth.auth_notes[ACTION_TOKEN_USER_ID] = user.id
    return processor.process_flow()


def test_authenticator_identifier_challenge_and_enabled_selection(reset, authenticators):
    from mini_keycloak.reset_credentials.authenticators import ATTEMPTED_USERNAME
    _, _, user, auth, executions = reset
    outcome = authenticators.process_flow()
    assert outcome.page == "account" and outcome.execution_id == executions[0].id
    assert auth.execution_status[executions[0].id] == "CHALLENGE"
    outcome = authenticators.process_action(executions[0].id, {"username": " RESET@EXAMPLE.TEST "})
    assert outcome.page == "login" and not outcome.complete
    assert auth.selected_user_id == user.id
    assert auth.auth_notes[ATTEMPTED_USERNAME] == "RESET@EXAMPLE.TEST"
    assert auth.execution_status == {executions[0].id: "SUCCESS", executions[1].id: "FORK"}
    message = db.session.scalar(select(ResetEmail))
    assert message.user_id == user.id and message.authentication_session_id == auth.tab_id


@pytest.mark.parametrize("account", ["unknown", "disabled", "email_less", "eligible"])
def test_authenticator_lookup_responses_are_uniform(reset, authenticators, account):
    _, _, user, auth, executions = reset
    identifier = user.username
    if account == "unknown":
        identifier = "unknown"
    elif account == "disabled":
        user.enabled = False
    elif account == "email_less":
        user.email = None
    authenticators.process_flow()
    outcome = authenticators.process_action(executions[0].id, {"username": identifier})
    assert outcome.page == "login"
    assert outcome.message == "If the account exists, reset instructions have been sent."
    assert not outcome.complete
    assert db.session.scalar(select(func.count(ResetEmail.id))) == (1 if account == "eligible" else 0)
    if account in {"unknown", "disabled"}:
        assert auth.selected_user_id is None


def test_authenticator_consumed_token_continuation_challenges_password(reset, authenticators):
    _, _, user, auth, executions = reset
    outcome = continue_token(reset, authenticators)
    assert outcome.page == "password" and outcome.execution_id == executions[2].id
    assert auth.selected_user_id == user.id
    assert auth.execution_status == {
        executions[0].id: "SUCCESS", executions[1].id: "SUCCESS", executions[2].id: "CHALLENGE"}
    assert db.session.scalar(select(func.count(ResetEmail.id))) == 1


@pytest.mark.parametrize("revisit", ["flow", "account_submission"])
def test_authenticator_pending_delivery_is_reused_on_revisit(reset, authenticators, revisit):
    from mini_keycloak.models import SecurityEvent
    from mini_keycloak.reset_credentials.authenticators import ACTION_TOKEN_USER_ID
    realm, _, user, auth, executions = reset
    authenticators.process_flow()
    initial = authenticators.process_action(executions[0].id, {"username": user.username})
    message = db.session.scalar(select(ResetEmail))
    message_id, raw = message.id, message.action_token
    db.session.commit()
    for _ in range(3):
        db.session.expire_all()
        outcome = (authenticators.process_flow() if revisit == "flow" else
                   authenticators.process_action(executions[0].id, {"username": user.username}))
        assert outcome == initial
        db.session.commit()
    messages = list(db.session.scalars(select(ResetEmail)))
    assert len(messages) == 1 and messages[0].id == message_id
    assert db.session.scalar(select(func.count(SecurityEvent.id)).where(
        SecurityEvent.event_type == "SEND_RESET_PASSWORD")) == 1
    service().consume(realm.name, raw)
    auth.auth_notes[ACTION_TOKEN_USER_ID] = user.id
    outcome = authenticators.process_flow()
    assert outcome.page == "password" and outcome.execution_id == executions[2].id
    assert db.session.scalar(select(func.count(ResetEmail.id))) == 1


def test_authenticator_delivery_marker_rolls_back_with_message(reset, authenticators):
    from mini_keycloak.models import SecurityEvent
    _, _, user, auth, executions = reset
    authenticators.process_flow()
    db.session.commit()
    original_notes = dict(auth.auth_notes)
    authenticators.process_action(executions[0].id, {"username": user.username})
    db.session.rollback()
    assert auth.auth_notes == original_notes
    assert db.session.scalar(select(func.count(ResetEmail.id))) == 0
    assert db.session.scalar(select(func.count(SecurityEvent.id))) == 0
    authenticators.process_action(executions[0].id, {"username": user.username})
    authenticators.process_flow()
    assert db.session.scalar(select(func.count(ResetEmail.id))) == 1
    assert db.session.scalar(select(func.count(SecurityEvent.id))) == 1


def test_authenticator_new_account_selection_starts_new_delivery(reset, authenticators):
    from mini_keycloak.models import SecurityEvent
    _, _, user, auth, executions = reset
    authenticators.process_flow()
    authenticators.process_action(executions[0].id, {"username": user.username})
    db.session.commit()
    auth.execution_status.clear()
    authenticators.process_flow()
    authenticators.process_action(executions[0].id, {"username": user.username})
    authenticators.process_flow()
    assert db.session.scalar(select(func.count(ResetEmail.id))) == 2
    assert db.session.scalar(select(func.count(SecurityEvent.id))) == 2


def test_authenticator_competing_delivery_rejects_stale_session(reset):
    from sqlalchemy.orm.exc import StaleDataError
    from mini_keycloak.authentication import AuthenticatorContext
    from mini_keycloak.models import AuthenticationExecution, Client, Realm, SecurityEvent
    from mini_keycloak.reset_credentials.authenticators import ResetCredentialEmail
    realm, client, _, auth, executions = reset
    factory = sessionmaker(bind=db.engine, expire_on_commit=False)
    with factory() as winner, factory() as loser:
        contexts = [AuthenticatorContext(AuthenticationRepository(session),
            session.get(AuthenticationSession, auth.tab_id), session.get(Realm, realm.id),
            session.get(Client, client.id), session.get(AuthenticationExecution, executions[1].id))
            for session in (winner, loser)]
        ResetCredentialEmail(service(winner)).authenticate(contexts[0])
        winner.commit()
        with pytest.raises(StaleDataError):
            ResetCredentialEmail(service(loser)).authenticate(contexts[1])
            loser.commit()
        loser.rollback()
    assert db.session.scalar(select(func.count(ResetEmail.id))) == 1
    assert db.session.scalar(select(func.count(SecurityEvent.id))) == 1


@pytest.mark.parametrize("stage", ["email", "password"])
@pytest.mark.parametrize("account", ["unavailable", "disabled"])
def test_authenticator_actions_reject_unavailable_selected_user(reset, authenticators, stage, account):
    _, _, user, auth, executions = reset
    if account == "unavailable":
        auth.selected_user_id = None
    else:
        user.enabled = False
    from mini_keycloak.authentication import AuthenticatorContext, FlowStatus
    from mini_keycloak.reset_credentials.authenticators import ResetCredentialEmail, ResetPassword
    index = 1 if stage == "email" else 2
    context = AuthenticatorContext(AuthenticationRepository(db.session), auth, reset[0], reset[1], executions[index])
    provider = ResetCredentialEmail(service()) if stage == "email" else ResetPassword()
    outcome = provider.action(context, {"password-new": "ChangedPassw0rd!", "password-confirm": "ChangedPassw0rd!"})
    assert outcome.status == FlowStatus.FAILURE
    assert IdentityRepository(db.session).password_matches(user, "OriginalPassw0rd!")


def test_authenticator_email_action_verifies_selected_enabled_user(reset, authenticators):
    _, _, user, auth, executions = reset
    authenticators.process_flow()
    authenticators.process_action(executions[0].id, {"username": user.username})
    outcome = authenticators.process_action(executions[1].id, {})
    assert outcome.page == "password"
    assert auth.execution_status[executions[1].id] == "SUCCESS"
    assert user.email_verified


def test_authenticator_password_operations_follow_email_completion(reset, authenticators):
    _, _, user, auth, executions = reset
    authenticators.process_flow()
    authenticators.process_action(executions[0].id, {"username": user.username})
    outcome = authenticators.process_action(executions[1].id, {})
    assert outcome.page == "password" and outcome.execution_id == executions[2].id
    outcome = authenticators.process_action(executions[2].id, {
        "password-new": "ChangedPassw0rd!", "password-confirm": "ChangedPassw0rd!"})
    assert outcome.complete and auth.execution_status[executions[2].id] == "SUCCESS"
    assert IdentityRepository(db.session).password_matches(user, "ChangedPassw0rd!")


@pytest.mark.parametrize("password,confirmation,policy", [
    ("", "", {}), ("ChangedPassw0rd!", "different", {}),
    ("short", "short", {"clauses": {"length": 12}}),
    ("ChangedPassw0rd!", "ChangedPassw0rd!", {"clauses": {"length": "12"}}),
    ("ChangedPassw0rd!", "ChangedPassw0rd!", {"clauses": {"unsupported": 1}}),
])
def test_authenticator_rejects_password_policy_and_confirmation(reset, authenticators, password, confirmation, policy):
    realm, _, user, auth, executions = reset
    continue_token(reset, authenticators)
    realm.password_policy = policy
    outcome = authenticators.process_action(executions[2].id,
        {"password-new": password, "password-confirm": confirmation})
    assert outcome.page == "password" and outcome.message and not outcome.complete
    assert auth.execution_status[executions[2].id] == "CHALLENGE"
    assert IdentityRepository(db.session).password_matches(user, "OriginalPassw0rd!")


def test_authenticator_password_update_events_and_caller_rollback(reset, authenticators):
    from mini_keycloak.models import SecurityEvent
    realm, client, user, auth, executions = reset
    realm.password_policy = {"clauses": {"length": 12, "digits": 1, "specialChars": 1}}
    continue_token(reset, authenticators)
    db.session.commit()
    outcome = authenticators.process_action(executions[2].id,
        {"password-new": "ChangedPassw0rd!", "password-confirm": "ChangedPassw0rd!"})
    assert outcome.complete and auth.execution_status[executions[2].id] == "SUCCESS"
    assert IdentityRepository(db.session).password_matches(user, "ChangedPassw0rd!")
    events = list(db.session.scalars(select(SecurityEvent).order_by(SecurityEvent.created_at)))
    assert [event.event_type for event in events] == ["SEND_RESET_PASSWORD", "UPDATE_PASSWORD", "UPDATE_CREDENTIAL"]
    for event in events:
        assert (event.realm_id, event.client_id, event.user_id) == (realm.id, client.id, user.id)
        assert event.details == {"code_id": auth.tab_id, "username": user.username, "email": user.email}
    db.session.rollback()
    assert IdentityRepository(db.session).password_matches(user, "OriginalPassw0rd!")
    assert db.session.scalar(select(func.count(SecurityEvent.id))) == 1


def test_authenticator_stale_password_writer_cannot_replace_completed_credential(reset, authenticators):
    from sqlalchemy.orm.exc import StaleDataError
    from mini_keycloak.authentication import AuthenticatorContext
    from mini_keycloak.reset_credentials.authenticators import ResetPassword
    from mini_keycloak.models import AuthenticationExecution, Client, Realm
    realm, client, user, auth, executions = reset
    continue_token(reset, authenticators)
    db.session.commit()
    factory = sessionmaker(bind=db.engine, expire_on_commit=False)
    with factory() as winner, factory() as loser:
        contexts = []
        for session in (winner, loser):
            contexts.append(AuthenticatorContext(AuthenticationRepository(session),
                session.get(AuthenticationSession, auth.tab_id), session.get(Realm, realm.id),
                session.get(Client, client.id), session.get(AuthenticationExecution, executions[2].id)))
        ResetPassword().action(contexts[0], {"password-new": "WinnerPassw0rd!", "password-confirm": "WinnerPassw0rd!"})
        winner.commit()
        with pytest.raises(StaleDataError):
            ResetPassword().action(contexts[1], {"password-new": "LaterPassw0rd!", "password-confirm": "LaterPassw0rd!"})
            loser.commit()
        loser.rollback()
    db.session.expire_all()
    assert IdentityRepository(db.session).password_matches(user, "WinnerPassw0rd!")
    assert not IdentityRepository(db.session).password_matches(user, "LaterPassw0rd!")


@pytest.mark.parametrize("raw", [None, b"token", 42, {}])
def test_consume_rejects_non_string_inputs(reset, raw):
    with pytest.raises(ValueError, match="^Invalid action token$"):
        service().consume(reset[0].name, raw)


def test_consume_rejects_encoded_bytes_even_when_signature_is_valid(reset):
    realm, _, user, auth, _ = reset
    message = service().issue(auth, user)
    with pytest.raises(ValueError, match="^Invalid action token$"):
        service().consume(realm.name, message.action_token.encode())
    assert message.consumed_at is None


@pytest.mark.parametrize("change", ["forgot_disabled", "session_client", "flow_provider"])
def test_action_tokens_require_current_reset_configuration(reset, change):
    realm, _, user, auth, _ = reset
    message = service().issue(auth, user)
    raw = message.action_token
    if change == "forgot_disabled":
        realm.forgot_password_allowed = False
    elif change == "flow_provider":
        AuthenticationRepository(db.session).get_flow(realm.id, auth.flow_id).provider_id = "different-flow"
    else:
        auth.client_id = IdentityRepository(db.session).create_client(
            realm.id, "other-client", redirect_uris=[auth.redirect_uri]).id
    with pytest.raises(ValueError, match="^Invalid action token$"):
        service().consume(realm.name, raw)
    assert message.consumed_at is None
