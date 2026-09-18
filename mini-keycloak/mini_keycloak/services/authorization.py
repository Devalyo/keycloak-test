from datetime import timedelta
import base64
import hashlib
import hmac
import re
import secrets

from sqlalchemy.orm import Session

from mini_keycloak.authentication.constants import AUTHENTICATION_FLOW_COMPLETED
from mini_keycloak.models import AuthorizationCode, Client, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.protocol import AuthorizationCodeRepository
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.sessions import UserSessionRepository
from mini_keycloak.oidc.errors import AccessDenied, InvalidGrant
from mini_keycloak.services.sessions import BrowserAuthenticationResult


class AuthorizationService:
    """Issue grants inside the caller's authentication transaction."""

    def __init__(self, session: Session, *, lifetime_seconds: int) -> None:
        self.session = session
        self.repository = AuthorizationCodeRepository(session)
        self.lifetime_seconds = lifetime_seconds

    def issue(self, result: BrowserAuthenticationResult) -> str:
        auth, user_session = result.authentication_session, result.user_session
        now = utc_now()
        if (auth.auth_notes.get(AUTHENTICATION_FLOW_COMPLETED) != 'true'
                or auth.current_execution == 'authenticated'
                or auth.selected_user_id not in (None, user_session.user_id)
                or AuthenticationRepository(self.session).get_session(auth.tab_id) is None
                or UserSessionRepository(self.session).eligible(user_session.sid, auth.realm_id, now) is None):
            raise AccessDenied()
        auth.selected_user_id = user_session.user_id
        auth.current_execution = 'authenticated'
        auth.auth_notes.pop(AUTHENTICATION_FLOW_COMPLETED, None)
        raw = secrets.token_urlsafe(32)
        self.repository.add(AuthorizationCode(
            code_hash=hashlib.sha256(raw.encode()).hexdigest(),
            realm_id=auth.realm_id, client_id=auth.client_id,
            user_id=user_session.user_id, user_session_id=user_session.id,
            redirect_uri=auth.redirect_uri, scope=auth.scope, nonce=auth.nonce,
            code_challenge=auth.code_challenge, code_challenge_method=auth.code_challenge_method,
            created_at=now,
            expires_at=now + timedelta(seconds=auth.realm.authorization_code_lifetime_seconds
                                       or self.lifetime_seconds),
        ))
        return raw

    def consume(self, raw: str, *, realm_id: str, client_id: str,
                redirect_uri: str, code_verifier: str | None = None) -> AuthorizationCode:
        """Validate and claim once; success stays uncommitted for token issuance.

        Any rejected grant rolls back the caller's transaction, including work
        performed by a concurrent loser. A successful caller must commit or
        roll back the eventual token response as one transaction.
        """
        try:
            code = self.repository.get(hashlib.sha256(raw.encode()).hexdigest())
            now = utc_now()
            if (code is None or code.realm_id != realm_id or code.client_id != client_id
                    or code.redirect_uri != redirect_uri or code.consumed_at is not None
                    or code.expires_at <= now):
                raise InvalidGrant()
            client = self.session.get(Client, client_id)
            user_session = self.session.get(UserSession, code.user_session_id)
            if (client is None or not client.enabled or not client.standard_flow_enabled
                    or client.realm_id != realm_id or user_session is None
                    or user_session.user_id != code.user_id
                    or UserSessionRepository(self.session).eligible(user_session.sid, realm_id, now) is None):
                raise InvalidGrant()
            if code.code_challenge is not None:
                if (code.code_challenge_method != 'S256'
                        or re.fullmatch(r'[A-Za-z0-9._~-]{43,128}', code_verifier or '') is None):
                    raise InvalidGrant()
                actual = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b'=')
                if not hmac.compare_digest(actual, code.code_challenge.encode()):
                    raise InvalidGrant()
            elif (code.code_challenge_method is not None or client.pkce_policy != 'optional'
                    or code_verifier is not None):
                raise InvalidGrant()
            consumed = self.repository.consume(code.id, realm_id=realm_id, client_id=client_id,
                                               redirect_uri=redirect_uri, now=utc_now())
            if consumed is None:
                raise InvalidGrant()
            return consumed
        except InvalidGrant:
            self.session.rollback()
            raise
