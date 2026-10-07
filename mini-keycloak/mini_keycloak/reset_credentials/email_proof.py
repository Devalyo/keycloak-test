from sqlalchemy import select

from mini_keycloak.authentication.constants import ACTION_TOKEN_USER_ID
from mini_keycloak.models import ResetEmail


def validated_user(context):
    auth, user = context.authentication_session, context.user
    if (user is None or not user.enabled
            or auth.auth_notes.get(ACTION_TOKEN_USER_ID) != user.id):
        return None
    message = context.repository.session.scalar(select(ResetEmail.id).where(
        ResetEmail.realm_id == context.realm.id,
        ResetEmail.client_id == context.client.id,
        ResetEmail.authentication_session_id == auth.tab_id,
        ResetEmail.user_id == user.id,
        ResetEmail.consumed_at.is_not(None),
        ResetEmail.consumed.is_(True),
    ).limit(1))
    return user if message is not None else None
