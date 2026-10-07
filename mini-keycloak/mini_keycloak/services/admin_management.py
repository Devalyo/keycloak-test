from sqlalchemy import delete, or_, select, update

from mini_keycloak.models import (
    AuthenticationExecution, AuthenticationFlow, AuthenticationSession,
    AuthorizationCode, Client, Credential, LoginFailureBucket, Realm,
    RealmKey, RefreshToken, ResetEmail, SecurityEvent, User, UserSession,
)


def delete_client(session, client: Client) -> None:
    owned = session.scalars(select(UserSession).where(UserSession.client_id == client.id)).all()
    for user_session in owned:
        other_client_id = session.scalar(select(RefreshToken.client_id).where(
            RefreshToken.user_session_id == user_session.id,
            RefreshToken.client_id != client.id,
        ).limit(1))
        if other_client_id is None:
            other_client_id = session.scalar(select(AuthorizationCode.client_id).where(
                AuthorizationCode.user_session_id == user_session.id,
                AuthorizationCode.client_id != client.id,
            ).limit(1))
        if other_client_id is not None:
            user_session.client_id = other_client_id
    session.flush()
    user_sessions = select(UserSession.id).where(UserSession.client_id == client.id)
    auth_sessions = select(AuthenticationSession.tab_id).where(
        AuthenticationSession.client_id == client.id)
    refreshes = select(RefreshToken.id).where(or_(
        RefreshToken.client_id == client.id,
        RefreshToken.user_session_id.in_(user_sessions),
    ))
    session.execute(delete(ResetEmail).where(or_(
        ResetEmail.client_id == client.id,
        ResetEmail.authentication_session_id.in_(auth_sessions),
    )))
    session.execute(update(SecurityEvent).where(
        SecurityEvent.client_id == client.id).values(client_id=None))
    session.execute(update(SecurityEvent).where(
        SecurityEvent.user_session_id.in_(user_sessions)).values(user_session_id=None))
    session.execute(delete(AuthorizationCode).where(or_(
        AuthorizationCode.client_id == client.id,
        AuthorizationCode.user_session_id.in_(user_sessions),
    )))
    session.execute(update(RefreshToken).where(
        RefreshToken.replaced_by_id.in_(refreshes)
    ).values(replaced_by_id=None))
    session.execute(delete(RefreshToken).where(or_(
        RefreshToken.client_id == client.id,
        RefreshToken.user_session_id.in_(user_sessions),
    )))
    session.execute(delete(AuthenticationSession).where(
        AuthenticationSession.client_id == client.id))
    session.execute(delete(UserSession).where(UserSession.client_id == client.id))
    session.execute(delete(Client).where(Client.id == client.id))


def delete_realm(session, realm: Realm) -> None:
    users = select(User.id).where(User.realm_id == realm.id)
    flows = select(AuthenticationFlow.id).where(AuthenticationFlow.realm_id == realm.id)
    refreshes = select(RefreshToken.id).where(RefreshToken.realm_id == realm.id)
    session.execute(delete(ResetEmail).where(ResetEmail.realm_id == realm.id))
    session.execute(delete(SecurityEvent).where(SecurityEvent.realm_id == realm.id))
    session.execute(delete(AuthorizationCode).where(AuthorizationCode.realm_id == realm.id))
    session.execute(update(RefreshToken).where(
        RefreshToken.replaced_by_id.in_(refreshes)
    ).values(replaced_by_id=None))
    session.execute(delete(RefreshToken).where(RefreshToken.realm_id == realm.id))
    session.execute(delete(AuthenticationSession).where(AuthenticationSession.realm_id == realm.id))
    session.execute(delete(UserSession).where(UserSession.realm_id == realm.id))
    session.execute(delete(LoginFailureBucket).where(LoginFailureBucket.realm_id == realm.id))
    session.execute(delete(Credential).where(Credential.user_id.in_(users)))
    session.execute(delete(User).where(User.realm_id == realm.id))
    session.execute(delete(Client).where(Client.realm_id == realm.id))
    session.execute(delete(RealmKey).where(RealmKey.realm_id == realm.id))
    session.execute(update(Realm).where(Realm.id == realm.id).values(
        reset_credentials_flow_id=None))
    session.execute(delete(AuthenticationExecution).where(
        AuthenticationExecution.flow_id.in_(flows)))
    session.execute(delete(AuthenticationFlow).where(AuthenticationFlow.realm_id == realm.id))
    session.execute(delete(Realm).where(Realm.id == realm.id))
