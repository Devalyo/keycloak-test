from datetime import timedelta
import hashlib
import logging
import re
import secrets
from urllib.parse import quote

from cryptography.fernet import InvalidToken as InvalidEncryptedKey
import jwt
from sqlalchemy import select

from mini_keycloak.models import Client, Realm, RealmKey, RefreshToken, User, UserSession
from mini_keycloak.models.identity import utc_now
from mini_keycloak.oidc.errors import InvalidGrant, InvalidRequest, InvalidScope, InvalidToken, RefreshReuse, TemporarilyUnavailable, UnauthorizedClient
from mini_keycloak.repositories.keys import RealmKeyRepository
from mini_keycloak.repositories.protocol import RefreshTokenRepository
from mini_keycloak.repositories.sessions import UserSessionRepository
from mini_keycloak.security.key_encryption import decrypt_private_pem
from mini_keycloak.services.sessions import UserSessionService, revoke_session
from mini_keycloak.services.events import request_event


def realm_issuer(realm: Realm, external_url: str) -> str:
    if realm.issuer_override:
        return realm.issuer_override.rstrip('/')
    return external_url.rstrip('/') + '/realms/' + quote(realm.name, safe='')


class TokenService:
    """Issue within the caller's transaction; verify against trusted realm state."""

    def __init__(self, session, *, external_url: str, master_secret: str,
                 access_seconds: int, refresh_seconds: int):
        self.session = session
        self.external_url = external_url
        self.master_secret = master_secret
        self.access_seconds = access_seconds
        self.refresh_seconds = refresh_seconds

    @staticmethod
    def bearer_token(*, authorization, form, query, method, content_type):
        """Accept one credential source; never accept bearer tokens in URLs."""
        if ('access_token' in query or len(form.getlist('access_token')) > 1
                or (authorization is not None and 'access_token' in form)):
            raise InvalidRequest()
        if authorization is not None:
            match = re.fullmatch(r'(?i:Bearer) +([^\s,]+)', authorization)
            if match is None:
                raise InvalidToken()
            return match[1]
        if ('access_token' in form and method == 'POST'
                and content_type == 'application/x-www-form-urlencoded' and form['access_token']):
            return form['access_token']
        raise InvalidToken()

    def verify_presented(self, raw: str, *, realm: Realm, token_type: str,
                         audience: str | None = None) -> dict:
        audience = self._presented_audience(raw, audience)
        return self.verify(raw, realm=realm, audience=audience, token_type=token_type)

    @staticmethod
    def _presented_audience(raw: str, audience: str | None) -> str:
        # The untrusted audience selects a client only. Every claim is then
        # verified against the selected realm key and persisted live state.
        if audience is None:
            try:
                audience = jwt.decode(raw, options={'verify_signature': False})['aud']
            except (jwt.PyJWTError, ValueError, TypeError, KeyError):
                raise InvalidToken() from None
        if not isinstance(audience, str) or not audience:
            raise InvalidToken()
        return audience

    def verify_logout_hint(self, raw: str, *, realm: Realm,
                           audience: str | None = None) -> dict:
        """Identify a retained session for logout, never authorize resource access.

        ID-token expiration alone is ignored. Session idle/max bounds still
        apply, including retries for a matching already-revoked session.
        """
        audience = self._presented_audience(raw, audience)
        claims = self._decode(raw, realm=realm, audience=audience, token_type='ID',
                              verify_expiration=False)
        if type(claims['exp']) is not int:
            raise InvalidToken()
        # Browser SSO retains the session's originating client even when a
        # subsequent client receives its own ID token for the shared session.
        audience_client = self.session.scalar(select(Client).where(
            Client.realm_id == realm.id, Client.client_id == audience, Client.enabled.is_(True)))
        if audience_client is None:
            raise InvalidToken()
        now = utc_now()
        user_session = self.session.scalar(select(UserSession)
            .join(Realm, Realm.id == UserSession.realm_id)
            .join(User, User.id == UserSession.user_id)
            .join(Client, Client.id == UserSession.client_id)
            .where(UserSession.sid == claims['sid'], UserSession.realm_id == realm.id,
                   User.realm_id == realm.id, Client.realm_id == realm.id,
                   UserSession.user_id == claims['sub'],
                   Realm.enabled.is_(True), User.enabled.is_(True), Client.enabled.is_(True),
                   UserSession.idle_expires_at > now, UserSession.max_expires_at > now))
        if (user_session is None
                or claims['auth_time'] != int(user_session.auth_time.timestamp())):
            raise InvalidToken()
        return claims

    def userinfo(self, raw: str, *, realm: Realm) -> dict:
        claims = self.verify_presented(raw, realm=realm, token_type='Bearer')
        user = self.session.get(User, claims['sub'])
        result = {'sub': user.id}
        scopes = set(claims['scope'].split())
        if 'profile' in scopes:
            result['preferred_username'] = user.username
        if 'email' in scopes:
            result.update(email=user.email, email_verified=user.email_verified)
        return result

    def password_grant(self, *, realm: Realm, client: Client, username: str,
                       password: str, scope: str | None, dummy_hash: str,
                       idle_seconds: int, max_seconds: int, throttle, source_address) -> dict:
        if not realm.password_grant_enabled or not client.direct_access_grants_enabled:
            raise UnauthorizedClient()
        requested = (scope if scope is not None else ' '.join(client.default_scopes)).split()
        if (not set(requested) <= {'openid', 'profile', 'email'}
                or not set(requested) <= set(client.default_scopes + client.optional_scopes)):
            raise InvalidScope()
        user, bucket_hash = throttle.authenticate(realm.id, username, password,
            source_address=source_address, dummy_hash=dummy_hash)
        throttle.clear(realm.id, bucket_hash)
        user_session = UserSessionService(self.session, idle_seconds=idle_seconds,
                                          max_seconds=max_seconds).create(realm, client, user)
        return self.issue(realm=realm, client=client, user_session=user_session,
                          scope=' '.join(dict.fromkeys(requested)))

    def issue(self, *, realm: Realm, client: Client, user_session: UserSession,
              scope: str, nonce: str | None = None, refresh_parent: RefreshToken | None = None) -> dict:
        now = utc_now()
        if (not realm.enabled or not client.enabled or client.realm_id != realm.id
                or UserSessionRepository(self.session).eligible(user_session.sid, realm.id, now) is None):
            raise InvalidGrant()
        user = self.session.get(User, user_session.user_id)
        key = RealmKeyRepository(self.session).get_active(realm.id)
        if key is None or key.algorithm != 'RS256':
            raise TemporarilyUnavailable()
        try:
            private_key = decrypt_private_pem(key.encrypted_private_pem, self.master_secret)
        except (InvalidEncryptedKey, ValueError):
            raise TemporarilyUnavailable() from None
        access_expiry = min(user_session.max_expires_at, now + timedelta(
            seconds=realm.access_token_lifetime_seconds or self.access_seconds))
        refresh_expiry = min(user_session.idle_expires_at, user_session.max_expires_at, now + timedelta(
            seconds=realm.refresh_token_lifetime_seconds or self.refresh_seconds))
        common = dict(iss=realm_issuer(realm, self.external_url), sub=user.id,
                      aud=client.client_id, azp=client.client_id, iat=int(now.timestamp()),
                      auth_time=int(user_session.auth_time.timestamp()), sid=user_session.sid, scope=scope)
        scopes = set(scope.split())
        if 'profile' in scopes:
            common['preferred_username'] = user.username
        if 'email' in scopes:
            common.update(email=user.email, email_verified=user.email_verified)

        def sign(typ, expiry, **extra):
            claims = dict(common, typ=typ, exp=int(expiry.timestamp()),
                          jti=secrets.token_urlsafe(32)) | extra
            return jwt.encode(claims, private_key, algorithm='RS256', headers={'kid': key.kid}), claims

        access, _ = sign('Bearer', access_expiry)
        generation = refresh_parent.generation + 1 if refresh_parent is not None else 0
        refresh, _ = sign('Refresh', refresh_expiry, generation=generation)
        refresh_row = RefreshToken(
            token_hash=hashlib.sha256(refresh.encode()).hexdigest(),
            realm_id=realm.id, client_id=client.id, user_id=user.id,
            user_session_id=user_session.id,
            family_id=refresh_parent.family_id if refresh_parent is not None else secrets.token_urlsafe(32),
            generation=generation, scope=scope, created_at=now, expires_at=refresh_expiry,
        )
        self.session.add(refresh_row)
        result = {'access_token': access, 'refresh_token': refresh, 'token_type': 'Bearer',
                  'expires_in': int(access_expiry.timestamp()) - int(now.timestamp()),
                  'refresh_expires_in': int(refresh_expiry.timestamp()) - int(now.timestamp()),
                  'not-before-policy': 0, 'session_state': user_session.sid, 'scope': scope}
        if 'openid' in scopes:
            result['id_token'], _ = sign('ID', access_expiry, **({'nonce': nonce} if nonce is not None else {}))
        self.session.flush()
        if refresh_parent is not None:
            refresh_parent.replaced_by_id = refresh_row.id
        return result

    def refresh(self, raw: str, *, realm: Realm, client: Client,
                scope: str | None = None, idle_seconds: int) -> dict:
        try:
            claims = self._decode(raw, realm=realm, audience=client.client_id, token_type='Refresh')
            repository = RefreshTokenRepository(self.session)
            digest = hashlib.sha256(raw.encode()).hexdigest()
            row = repository.get(digest, realm.id, client.id)
            if row is None:
                raise InvalidToken()
            now = utc_now()
            user_session = repository.lock_session(row.user_session_id, now)
            now = utc_now()
            if (user_session is None or user_session.sid != claims['sid']
                    or UserSessionRepository(self.session).eligible(claims['sid'], realm.id, now) is None):
                raise InvalidToken()
            # Refresh the row after obtaining the session lock: another worker
            # may have consumed it while this transaction was waiting.
            row = repository.get(digest, realm.id, client.id)
            if not self._refresh_matches(row, claims, user_session, now):
                raise InvalidToken()
            if row.used_at is not None:
                revoke_session(self.session, user_session.sid, realm.id)
                try:
                    # Audit storage failures must not undo defensive revocation.
                    # The savepoint also recovers from a failed database flush.
                    with self.session.begin_nested():
                        request_event(self.session, realm.id, 'REFRESH_TOKEN_REUSE', client_id=client.id,
                            user_id=user_session.user_id, user_session_id=user_session.id,
                            error='refresh_reuse', details={'grant_type': 'refresh_token', 'reason': 'reuse'})
                except Exception:
                    logging.getLogger(__name__).error('Refresh reuse event persistence failed')
                raise RefreshReuse()
            requested = (scope if scope is not None else row.scope).split()
            if not set(requested) <= set(row.scope.split()):
                raise InvalidScope()
            consumed = repository.consume(row.id, now)
            if consumed is None:
                raise InvalidToken()
            user_session.last_refresh_at = now
            user_session.idle_expires_at = min(user_session.max_expires_at, now + timedelta(
                seconds=realm.sso_idle_lifetime_seconds or idle_seconds))
            return self.issue(realm=realm, client=client, user_session=user_session,
                              scope=' '.join(dict.fromkeys(requested)), refresh_parent=consumed)
        except InvalidToken:
            raise InvalidGrant() from None

    @staticmethod
    def _refresh_matches(row, claims, user_session, now):
        return (row is not None and row.revoked_at is None and row.expires_at > now
                and claims['exp'] > int(now.timestamp())
                and row.user_id == user_session.user_id == claims['sub']
                and row.user_session_id == user_session.id and row.scope == claims['scope']
                and type(claims.get('generation')) is int and row.generation == claims['generation']
                and int(row.expires_at.timestamp()) == claims['exp']
                and int(user_session.auth_time.timestamp()) == claims['auth_time'])

    def _decode(self, raw: str, *, realm: Realm, audience: str, token_type: str,
                verify_expiration: bool = True) -> dict:
        try:
            header = jwt.get_unverified_header(raw)
            if header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str):
                raise InvalidToken()
            key = self.session.scalar(select(RealmKey).where(
                RealmKey.realm_id == realm.id, RealmKey.kid == header['kid'], RealmKey.algorithm == 'RS256'))
            if key is None:
                raise InvalidToken()
            public_key = jwt.PyJWK.from_dict(key.public_jwk, algorithm='RS256').key
            claims = jwt.decode(raw, public_key, algorithms=['RS256'],
                                issuer=realm_issuer(realm, self.external_url), audience=audience,
                                options={'verify_exp': verify_expiration,
                                         'require': ['iss', 'sub', 'aud', 'azp', 'exp', 'iat',
                                                     'auth_time', 'jti', 'typ', 'sid', 'scope']})
            if (claims['typ'] != token_type or token_type not in {'Bearer', 'ID', 'Refresh'}
                    or claims['aud'] != audience or claims['azp'] != audience
                    or any(not isinstance(claims[name], str) for name in ('sid', 'scope', 'jti'))):
                raise InvalidToken()
            return claims
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            raise InvalidToken() from None

    def verify(self, raw: str, *, realm: Realm, audience: str, token_type: str) -> dict:
        claims = self._decode(raw, realm=realm, audience=audience, token_type=token_type)
        now = utc_now()
        user_session = UserSessionRepository(self.session).eligible(claims['sid'], realm.id, now)
        client = self.session.scalar(select(Client).where(
            Client.realm_id == realm.id, Client.client_id == audience, Client.enabled.is_(True)))
        if (user_session is None or client is None or user_session.user_id != claims['sub']
                or claims['auth_time'] != int(user_session.auth_time.timestamp())):
            raise InvalidToken()
        if token_type == 'Refresh':
            row = RefreshTokenRepository(self.session).get(
                hashlib.sha256(raw.encode()).hexdigest(), realm.id, client.id)
            if not self._refresh_matches(row, claims, user_session, now) or row.used_at is not None:
                raise InvalidToken()
        return claims
