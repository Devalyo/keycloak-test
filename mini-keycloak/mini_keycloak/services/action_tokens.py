"""Signed, single-use reset messages within the caller's transaction."""

from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import hashlib
import hmac
import secrets

from flask import current_app
import jwt

from mini_keycloak.models import AuthenticationSession, Client, Realm, ResetEmail, User
from mini_keycloak.models.identity import utc_now
from mini_keycloak.repositories.authentication import AuthenticationRepository
from mini_keycloak.repositories.identity import IdentityRepository


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


@dataclass(frozen=True)
class ConsumedActionToken:
    token_type: str
    authentication_session: AuthenticationSession
    user: User


class ResetActionTokenService:
    def __init__(self, session, *, secret=None, lifetime_seconds=1800):
        self.session = session
        self.repository = AuthenticationRepository(session)
        self.secret = secret if secret is not None else current_app.config["SECRET_KEY"]
        self.lifetime_seconds = lifetime_seconds

    def _validate_relationships(self, auth, user, realm, now):
        client = self.session.get(Client, auth.client_id) if auth is not None else None
        if (realm is None or not realm.enabled or not realm.forgot_password_allowed
                or auth is None or user is None
                or not user.enabled or not user.email or user.realm_id != realm.id
                or auth.realm_id != realm.id or auth.selected_user_id != user.id
                or _utc(auth.expires_at) <= now or client is None or not client.enabled
                or not client.standard_flow_enabled or client.realm_id != realm.id
                or auth.flow_id is None or realm.reset_credentials_flow_id != auth.flow_id):
            raise ValueError("Invalid action token")
        flow = self.repository.get_flow(realm.id, auth.flow_id)
        if flow is None or flow.provider_id != "basic-flow":
            raise ValueError("Invalid action token")

    def issue(self, auth: AuthenticationSession, user: User) -> ResetEmail:
        now = utc_now().replace(microsecond=0)
        realm = self.session.get(Realm, auth.realm_id)
        self._validate_relationships(auth, user, realm, now)
        expires = min(now + timedelta(seconds=self.lifetime_seconds), _utc(auth.expires_at)).replace(microsecond=0)
        if expires <= now:
            raise ValueError("Invalid action token")
        token_id = secrets.token_urlsafe(32)
        claims = dict(typ="reset-credentials", jti=token_id, sub=user.id,
                      realm_id=realm.id, client_id=auth.client_id, asid=auth.tab_id,
                      iat=int(now.timestamp()), exp=int(expires.timestamp()))
        raw = jwt.encode(claims, self.secret, algorithm="HS256")
        message = ResetEmail(
            realm_id=realm.id, client_id=auth.client_id, user_id=user.id,
            authentication_session_id=auth.tab_id, recipient=user.email,
            token_id=token_id, action_token=raw,
            action_token_hash=hashlib.sha256(raw.encode()).hexdigest(),
            created_at=now, expires_at=expires,
        )
        self.session.add(message)
        self.session.flush()
        return message

    def consume(self, realm_name: str, raw_token: str) -> ConsumedActionToken:
        if not isinstance(raw_token, str):
            raise ValueError("Invalid action token")
        try:
            claims = jwt.decode(raw_token, self.secret, algorithms=["HS256"], options={
                "require": ["typ", "jti", "sub", "realm_id", "client_id", "asid", "iat", "exp"],
            })
            strings = {"typ", "jti", "sub", "realm_id", "client_id", "asid"}
            if (set(claims) != strings | {"iat", "exp"}
                    or any(type(claims[key]) is not str or not claims[key] for key in strings)
                    or type(claims["iat"]) is not int or type(claims["exp"]) is not int
                    or claims["iat"] >= claims["exp"]):
                raise ValueError("Invalid action token")
        except (jwt.PyJWTError, TypeError, ValueError):
            raise ValueError("Invalid action token") from None
        realm = IdentityRepository(self.session).get_realm(realm_name)
        message = self.repository.get_reset_email(claims["jti"])
        now = utc_now()
        if (realm is None or message is None or realm.id != claims["realm_id"]
                or message.realm_id != claims["realm_id"] or message.user_id != claims["sub"]
                or message.client_id != claims["client_id"]
                or message.authentication_session_id != claims["asid"]
                or message.consumed_at is not None or message.consumed
                or _utc(message.expires_at) <= now
                or int(_utc(message.created_at).timestamp()) != claims["iat"]
                or int(_utc(message.expires_at).timestamp()) != claims["exp"]
                or not hmac.compare_digest(message.action_token_hash,
                                           hashlib.sha256(raw_token.encode()).hexdigest())):
            raise ValueError("Invalid action token")
        auth = self.repository.get_session(claims["asid"])
        user = self.session.get(User, claims["sub"])
        self._validate_relationships(auth, user, realm, now)
        if auth.client_id != claims["client_id"]:
            raise ValueError("Invalid action token")
        if self.repository.consume_reset_email(message, utc_now()) is None:
            raise ValueError("Invalid action token")
        return ConsumedActionToken(claims["typ"], auth, user)
