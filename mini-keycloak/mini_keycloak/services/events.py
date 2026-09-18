from ipaddress import ip_address

from flask import has_request_context, request

from mini_keycloak.models import Client, Realm, User, UserSession
from mini_keycloak.repositories.events import EventRepository
from mini_keycloak.repositories.identity import IdentityRepository
from mini_keycloak.security.logging import log_failure


EVENT_TYPES = frozenset({
    'LOGIN', 'LOGIN_ERROR', 'CODE_TO_TOKEN', 'CODE_TO_TOKEN_ERROR',
    'PASSWORD_GRANT', 'PASSWORD_GRANT_ERROR', 'REFRESH_TOKEN',
    'REFRESH_TOKEN_ERROR', 'REFRESH_TOKEN_REUSE', 'LOGOUT', 'LOGOUT_ERROR', 'TOKEN_ERROR',
})
ERRORS = frozenset({'invalid_request', 'invalid_credentials', 'invalid_client', 'invalid_grant',
                   'invalid_token', 'invalid_scope', 'unauthorized_client', 'access_denied',
                   'unsupported_grant_type', 'temporarily_unavailable', 'server_error', 'refresh_reuse'})
DETAIL_VALUES = {
    'grant_type': {'authorization_code', 'refresh_token', 'password'},
    'auth_method': {'none', 'client_secret_basic', 'client_secret_post'},
    'reason': {'credentials', 'browser_binding', 'origin', 'protocol', 'reuse'},
}


class EventService:
    """Project trusted identifiers and finite detail values; caller owns commit.

    No free-text request values, exception messages, hashes or bearer handles
    belong in events. Even values under permitted keys must match an enum.
    """

    def __init__(self, session):
        self.session = session

    def record(self, realm_id, event_type, *, client_id=None, user_id=None,
               user_session_id=None, source_address=None, error=None, details=None):
        if event_type not in EVENT_TYPES or self.session.get(Realm, realm_id) is None:
            raise ValueError('Invalid event identity')
        for model, identifier in ((Client, client_id), (User, user_id), (UserSession, user_session_id)):
            if identifier is not None:
                entity = self.session.get(model, identifier)
                if entity is None or entity.realm_id != realm_id:
                    raise ValueError('Invalid event identity')
                if model is UserSession and user_id is not None and entity.user_id != user_id:
                    raise ValueError('Invalid event identity')
        try:
            source_address = str(ip_address(source_address)) if source_address else None
        except ValueError:
            source_address = None
        safe_details = {key: value[:64] for key, value in (details or {}).items()
                        if key in DETAIL_VALUES and isinstance(value, str)
                        and value in DETAIL_VALUES[key]}
        return EventRepository(self.session).add(
            realm_id=realm_id, event_type=event_type, client_id=client_id, user_id=user_id,
            user_session_id=user_session_id, source_address=source_address,
            error=(error if error in ERRORS else 'invalid_request') if error is not None else None,
            details=safe_details)


def request_event(session, realm_id, event_type, **values):
    """Use the direct peer address; forwarded headers are not trusted."""
    return EventService(session).record(realm_id, event_type,
        source_address=request.remote_addr if has_request_context() else None, **values)


def request_failure(session, realm_name, event_type, **values):
    """Persist after caller rollback; audit outages never expose SQL parameters."""
    try:
        realm = IdentityRepository(session).get_realm(realm_name)
        if realm is not None:
            request_event(session, realm.id, event_type, **values)
            session.commit()
    except Exception:
        session.rollback()
        log_failure('audit')
