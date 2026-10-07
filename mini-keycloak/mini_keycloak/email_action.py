from __future__ import annotations

from mini_keycloak.store import AuthenticationSession, InMemoryStore


def consume_reset_email(
    store: InMemoryStore, session: AuthenticationSession, user_id: str, token: str
) -> bool:
    for message in store.outbox:
        if (
            message.action_token == token
            and message.user_id == user_id
            and message.tab_id == session.tab_id
            and not message.consumed
        ):
            message.consumed = True
            session.auth_notes["action.token.user.id"] = user_id
            return True
    return False


def email_action_completed(
    store: InMemoryStore, session: AuthenticationSession, user_id: str
) -> bool:
    return session.auth_notes.get("action.token.user.id") == user_id and any(
        message.user_id == user_id
        and message.tab_id == session.tab_id
        and message.consumed
        for message in store.outbox
    )
