from sqlalchemy import delete, or_, select, update

from mini_keycloak.models import AuthenticationSession, AuthorizationCode, LoginFailureBucket, RefreshToken, SecurityEvent, UserSession
from mini_keycloak.models.identity import utc_now


def cleanup_expired(session, *, batch_size=100):
    """Delete expired state in stable, independently committed batches.

    A fixed cutoff makes one run deterministic. Children of inactive sessions
    are unusable even if their own expiry is later. Retain revoked sessions
    through their idle/max window for authenticated logout retries. Retain audit
    rows, unlinking their nullable references only when the session expires.
    """
    if not isinstance(batch_size, int) or not 1 <= batch_size <= 1000:
        raise ValueError('batch_size must be between 1 and 1000')
    cutoff = utc_now()
    expired = or_(UserSession.idle_expires_at <= cutoff, UserSession.max_expires_at <= cutoff)
    inactive = or_(UserSession.revoked_at.is_not(None), expired)
    inactive_ids = select(UserSession.id).where(inactive)
    specifications = (
        (AuthenticationSession, AuthenticationSession.tab_id, AuthenticationSession.expires_at <= cutoff),
        (AuthorizationCode, AuthorizationCode.id, or_(AuthorizationCode.expires_at <= cutoff,
            AuthorizationCode.user_session_id.in_(inactive_ids))),
        (RefreshToken, RefreshToken.id, or_(RefreshToken.expires_at <= cutoff,
            RefreshToken.revoked_at.is_not(None), RefreshToken.user_session_id.in_(inactive_ids))),
        (UserSession, UserSession.id, expired),
        (LoginFailureBucket, LoginFailureBucket.id, LoginFailureBucket.expires_at <= cutoff),
    )
    counts = {}
    try:
        for model, primary_key, predicate in specifications:
            counts[model.__tablename__] = 0
            while True:
                identifiers = session.scalars(select(primary_key).where(predicate)
                    .order_by(primary_key).limit(batch_size)).all()
                if not identifiers:
                    break
                if model is RefreshToken:
                    session.execute(update(RefreshToken).where(RefreshToken.replaced_by_id.in_(identifiers))
                                    .values(replaced_by_id=None).execution_options(synchronize_session=False))
                elif model is UserSession:
                    session.execute(update(SecurityEvent).where(SecurityEvent.user_session_id.in_(identifiers))
                                    .values(user_session_id=None).execution_options(synchronize_session=False))
                deleted = session.execute(delete(model).where(primary_key.in_(identifiers), predicate)
                                          .execution_options(synchronize_session=False)).rowcount
                session.commit()
                counts[model.__tablename__] += deleted
        return counts
    except Exception:
        session.rollback()
        raise
