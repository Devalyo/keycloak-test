import hashlib
import hmac
import re
import secrets

from flask import current_app, request

from mini_keycloak.models import AuthenticationSession
from mini_keycloak.store import PersistentStore


PREAUTH_COOKIE_PREFIX = "mini_keycloak_login_"


class SessionContinuation:
    @staticmethod
    def _digest(raw_code: str) -> str:
        return hashlib.sha256(raw_code.encode()).hexdigest()

    @classmethod
    def issue(cls, auth: AuthenticationSession) -> str:
        raw_code = secrets.token_urlsafe(32)
        auth.session_code_hash = cls._digest(raw_code)
        return raw_code

    @classmethod
    def verify(cls, auth: AuthenticationSession, raw_code: str) -> bool:
        if not isinstance(raw_code, str):
            return False
        return hmac.compare_digest(auth.session_code_hash, cls._digest(raw_code))

    @classmethod
    def replace(cls, auth: AuthenticationSession) -> str:
        return cls.issue(auth)

    @classmethod
    def rotate(cls, auth: AuthenticationSession, raw_code: str) -> str:
        if not cls.verify(auth, raw_code):
            raise ValueError("Invalid authentication request")
        return cls.replace(auth)


def _binding_secret() -> bytes:
    secret = current_app.secret_key
    return secret.encode() if isinstance(secret, str) else secret


def browser_binding(auth: AuthenticationSession) -> str:
    message = (
        f"mini-keycloak:authentication-session:v1\0{auth.realm_id}\0"
        f"{auth.client_id}\0{auth.tab_id}\0{auth.browser_binding_generation}"
    ).encode()
    return hmac.new(_binding_secret(), message, "sha256").hexdigest()


def binding_matches(auth: AuthenticationSession, presented: str) -> bool:
    if not isinstance(presented, str) or re.fullmatch(r"[0-9a-f]{64}", presented) is None:
        return False
    return hmac.compare_digest(browser_binding(auth), presented)


class SessionCodeChecks:
    def __init__(self, store: PersistentStore) -> None:
        self.store = store
        self._validated_tab_id: str | None = None
        self._validated_code: str | None = None

    def validate(
        self,
        realm_name: str,
        expected_execution: str | None = None,
        *,
        require_standard_flow: bool = True,
    ) -> AuthenticationSession:
        tab_id = request.args.get("tab_id", "")
        authentication_session = self.store.get_auth_session(tab_id)
        raw_code = request.args.get("session_code", "")
        if (
            authentication_session is None
            or authentication_session.realm.name != realm_name
            or request.args.get("client_id")
            != authentication_session.client.client_id
            or not authentication_session.client.enabled
            or (
                require_standard_flow
                and not authentication_session.client.standard_flow_enabled
            )
            or authentication_session.current_execution == "authenticated"
            or (
                expected_execution is not None
                and request.args.get("execution") != expected_execution
            )
            or not binding_matches(
                authentication_session,
                request.cookies.get(PREAUTH_COOKIE_PREFIX + tab_id, ""),
            )
            or not SessionContinuation.verify(authentication_session, raw_code)
        ):
            raise ValueError("Invalid authentication request")
        self._validated_tab_id = authentication_session.tab_id
        self._validated_code = raw_code
        return authentication_session

    def rotate(self, authentication_session: AuthenticationSession) -> str:
        if (
            self._validated_tab_id != authentication_session.tab_id
            or self._validated_code is None
        ):
            raise ValueError("Invalid authentication request")
        return SessionContinuation.rotate(
            authentication_session, self._validated_code
        )
