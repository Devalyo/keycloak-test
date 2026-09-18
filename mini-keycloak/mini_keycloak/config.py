from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace
import hashlib
import ipaddress
import os
import re
import unicodedata
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from sqlalchemy.engine import make_url


def _invalid(name: str) -> ValueError:
    # Never include configuration values or a parser's original exception.
    return ValueError('MINI_KEYCLOAK_' + name)


def _positive_integer(value: object, name: str) -> int:
    if isinstance(value, str) and re.fullmatch(r'[0-9]+', value):
        try:
            value = int(value)
        except ValueError:
            raise _invalid(name) from None
    if type(value) is not int or value <= 0:
        raise _invalid(name)
    return value


def positive_integer_from_env(name: str, default: int) -> int:
    return _positive_integer(os.getenv(name, str(default)), name.removeprefix('MINI_KEYCLOAK_'))


def _boolean(value: object, name: str) -> bool:
    if type(value) is bool:
        return value
    if isinstance(value, str):
        value = value.strip().lower()
        if value in {'true', '1'}:
            return True
        if value in {'false', '0'}:
            return False
    raise _invalid(name)


def boolean_from_env(name: str, default: bool) -> bool:
    return _boolean(os.getenv(name, str(default)), name.removeprefix('MINI_KEYCLOAK_'))


def _list(value: object, name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        value = tuple(item.strip() for item in value.split(','))
    if not isinstance(value, (tuple, list)) or not value or any(
            not isinstance(item, str) or not item or item != item.strip() for item in value):
        raise _invalid(name)
    return tuple(value)


def _host(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise _invalid(name)
    if value.startswith('[') and value.endswith(']'):
        try:
            return '[' + ipaddress.IPv6Address(value[1:-1]).compressed + ']'
        except ValueError:
            raise _invalid(name) from None
    try:
        host = value.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise _invalid(name) from None
    if len(host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                              for label in host.split('.')):
        raise _invalid(name)
    return host


def _external_url(value: object, production: bool) -> str:
    name = 'EXTERNAL_URL'
    if not isinstance(value, str) or not value or any(
            ord(char) <= 32 or ord(char) == 127 or char in '\\?#%' for char in value):
        raise _invalid(name)
    try:
        parsed = urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname
    except ValueError:
        raise _invalid(name) from None
    if (parsed.scheme not in ({'https'} if production else {'http', 'https'})
            or not hostname or parsed.username is not None or parsed.password is not None
            or parsed.netloc.endswith(':') or (port is not None and not 1 <= port <= 65535)):
        raise _invalid(name)
    host = _host('[' + hostname + ']' if ':' in hostname else hostname, name)
    path = parsed.path.rstrip('/')
    # Local prefix metadata is historical compatibility only: routes, forms,
    # and cookie paths are not mounted under it. Production supports origins.
    if production and path:
        raise _invalid(name)
    if '//' in parsed.path or any(segment in {'.', '..'} or not re.fullmatch(r'[A-Za-z0-9._~-]+', segment)
                                  for segment in path.split('/')[1:]):
        raise _invalid(name)
    authority = host
    if port is not None and port != {'http': 80, 'https': 443}[parsed.scheme]:
        authority += ':' + str(port)
    return urlunsplit((parsed.scheme, authority, path, '', ''))


def _database_query(raw: str, parsed_query: Mapping) -> None:
    name = 'DATABASE_URL'
    # Inspect the raw query as well: SQLAlchemy drops blank values and represents
    # repeated values as tuples. Neither can be accepted as an operator choice.
    pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True,
                      errors='strict', max_num_fields=3)
    query = dict(pairs)
    if not pairs or len(query) != len(pairs) or query != dict(parsed_query):
        raise _invalid(name)
    if set(query) - {'sslmode', 'connect_timeout', 'sslrootcert'}:
        raise _invalid(name)
    mode = query.get('sslmode')
    if mode is not None and mode not in {'require', 'verify-ca', 'verify-full'}:
        raise _invalid(name)
    timeout = query.get('connect_timeout')
    if timeout is not None and (not re.fullmatch(r'[1-9][0-9]?', timeout) or int(timeout) > 60):
        raise _invalid(name)
    root_cert = query.get('sslrootcert')
    if (mode in {'verify-ca', 'verify-full'}) != (root_cert is not None):
        raise _invalid(name)
    if root_cert is not None and (
            not root_cert.startswith('/') or len(root_cert.encode('utf-8')) > 4096
            or root_cert != root_cert.strip()
            or any(part in {'', '.', '..'} for part in root_cert.split('/')[1:])
            or any(unicodedata.category(char).startswith('C') or char in '\\?#%' for char in root_cert)):
        raise _invalid(name)


def _database_url(value: object, production: bool) -> str:
    name = 'DATABASE_URL'
    if not isinstance(value, str) or not value or any(ord(char) <= 32 or ord(char) == 127 for char in value):
        raise _invalid(name)
    try:
        parsed = make_url(value)
        if production and (parsed.drivername != 'postgresql+psycopg' or not parsed.host or not parsed.database
                           or parsed.port is not None and not 1 <= parsed.port <= 65535):
            raise _invalid(name)
        if parsed.get_backend_name() == 'postgresql':
            # Credentials belong to the database URL; public URL credentials are forbidden.
            if not parsed.host or not parsed.database or '#' in value or '\\' in value:
                raise _invalid(name)
            _host('[' + parsed.host + ']' if ':' in parsed.host else parsed.host, name)
            if '?' in value:
                _database_query(value.partition('?')[2], parsed.query)
    except Exception:
        raise _invalid(name) from None
    return value


_CONFIG_KEYS = {'database_url': 'SQLALCHEMY_DATABASE_URI'}
_LOCAL_SECRET = 'local-development-secret-change-me'


@dataclass(frozen=True)
class Settings:
    database_url: str = field(default='sqlite:///mini-keycloak.db', repr=False)
    external_url: str = 'http://127.0.0.1:5000'
    secret_key: str | bytes = field(default=_LOCAL_SECRET, repr=False)
    oidc_key_encryption_secret: str | None = field(default=None, repr=False)
    access_token_lifetime_seconds: int = 300
    authorization_code_lifetime_seconds: int = 60
    refresh_token_lifetime_seconds: int = 1800
    sso_idle_lifetime_seconds: int = 1800
    sso_max_lifetime_seconds: int = 36000
    session_cookie_secure: bool = False
    profile: str = 'local'
    database_pool_size: int = 5
    database_max_overflow: int = 10
    database_pool_timeout_seconds: int = 30
    database_pool_recycle_seconds: int = 1800
    log_level: str = 'INFO'
    trusted_hosts: tuple[str, ...] | None = None
    proxy_mode: str | None = None
    trusted_proxy_cidrs: tuple[str, ...] = ()
    proxy_hops: int = 1
    login_failure_threshold: int = 5
    login_failure_window_seconds: int = 300
    login_lock_seconds: int = 60

    @classmethod
    def from_env(cls, *, overrides: Mapping[str, object] | None = None) -> Settings:
        values = {item.name: os.getenv('MINI_KEYCLOAK_' + item.name.upper(), item.default)
                  for item in fields(cls)}
        settings = cls(**values)
        return settings._with_overrides(overrides)._validated(
            explicit_master_none='OIDC_KEY_ENCRYPTION_SECRET' in (overrides or {}))

    def _with_overrides(self, overrides: Mapping[str, object] | None) -> Settings:
        overrides = overrides or {}
        if self.profile == 'production' and overrides.get('PROFILE', 'production') != 'production':
            raise _invalid('PROFILE')
        return replace(self, **{item.name: overrides[_CONFIG_KEYS.get(item.name, item.name.upper())]
                               for item in fields(self)
                               if _CONFIG_KEYS.get(item.name, item.name.upper()) in overrides})

    def _validated(self, *, explicit_master_none: bool = False) -> Settings:
        if self.profile not in ('local', 'production'):
            raise _invalid('PROFILE')
        production = self.profile == 'production'
        normalized = {}
        for item in fields(self):
            if item.name.endswith('_seconds') or item.name in {'database_pool_size', 'database_max_overflow', 'proxy_hops', 'login_failure_threshold'}:
                normalized[item.name] = _positive_integer(getattr(self, item.name), item.name.upper())
        if normalized['proxy_hops'] > 8:
            raise _invalid('PROXY_HOPS')
        normalized['database_url'] = _database_url(self.database_url, production)
        normalized['external_url'] = _external_url(self.external_url, production)
        normalized['session_cookie_secure'] = _boolean(self.session_cookie_secure, 'SESSION_COOKIE_SECURE')
        if production and not normalized['session_cookie_secure']:
            raise _invalid('SESSION_COOKIE_SECURE')
        if not isinstance(self.secret_key, (str, bytes)) or not self.secret_key.strip():
            raise _invalid('SECRET_KEY')
        try:
            secret = self.secret_key.encode('utf-8') if isinstance(self.secret_key, str) else self.secret_key
        except UnicodeError:
            raise _invalid('SECRET_KEY') from None
        if production and (len(secret) < 32 or secret == _LOCAL_SECRET.encode()):
            raise _invalid('SECRET_KEY')
        master = self.oidc_key_encryption_secret
        if master is None and not production and not explicit_master_none:
            master = base64.urlsafe_b64encode(hashlib.sha256(
                b'mini-keycloak/local-development/oidc-key-encryption\0' + secret).digest()).decode('ascii')
        if not isinstance(master, str) or not master.strip():
            raise _invalid('OIDC_KEY_ENCRYPTION_SECRET')
        try:
            master_bytes = master.encode('utf-8')
        except UnicodeError:
            raise _invalid('OIDC_KEY_ENCRYPTION_SECRET') from None
        if production and (len(master_bytes) < 32 or master_bytes == secret):
            raise _invalid('OIDC_KEY_ENCRYPTION_SECRET')
        # Leave local fallback unresolved until final factory overrides are merged.
        normalized['oidc_key_encryption_secret'] = self.oidc_key_encryption_secret
        hostname = urlsplit(normalized['external_url']).hostname
        external_host = '[' + hostname + ']' if ':' in hostname else hostname
        if self.trusted_hosts is None:
            if production:
                raise _invalid('TRUSTED_HOSTS')
            hosts = ('localhost', '127.0.0.1', '[::1]', external_host)
        else:
            hosts = _list(self.trusted_hosts, 'TRUSTED_HOSTS')
        normalized['trusted_hosts'] = tuple(dict.fromkeys(_host(host, 'TRUSTED_HOSTS') for host in hosts))
        if production and external_host not in normalized['trusted_hosts']:
            raise _invalid('TRUSTED_HOSTS')
        mode = self.proxy_mode
        if mode is None and not production:
            mode = 'none'
        if mode not in ('none', 'xforwarded'):
            raise _invalid('PROXY_MODE')
        normalized['proxy_mode'] = mode
        cidrs = ()
        if self.trusted_proxy_cidrs:
            try:
                cidrs = tuple(str(ipaddress.ip_network(cidr, strict=True))
                              for cidr in _list(self.trusted_proxy_cidrs, 'TRUSTED_PROXY_CIDRS'))
            except ValueError:
                raise _invalid('TRUSTED_PROXY_CIDRS') from None
        elif isinstance(self.trusted_proxy_cidrs, str):
            raise _invalid('TRUSTED_PROXY_CIDRS')
        if mode == 'xforwarded' and not cidrs:
            raise _invalid('TRUSTED_PROXY_CIDRS')
        normalized['trusted_proxy_cidrs'] = cidrs
        if self.log_level not in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
            raise _invalid('LOG_LEVEL')
        return replace(self, **normalized)

    def as_flask_config(self, *, overrides: Mapping[str, object] | None = None) -> dict[str, object]:
        settings = self._with_overrides(overrides)._validated(
            explicit_master_none='OIDC_KEY_ENCRYPTION_SECRET' in (overrides or {}))
        config = dict(overrides or {})
        config.update({_CONFIG_KEYS.get(item.name, item.name.upper()): getattr(settings, item.name)
                       for item in fields(settings)})
        config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', False)
        config['TRUSTED_HOSTS'] = list(settings.trusted_hosts)
        if settings.oidc_key_encryption_secret is None:
            secret = settings.secret_key.encode() if isinstance(settings.secret_key, str) else settings.secret_key
            config['OIDC_KEY_ENCRYPTION_SECRET'] = base64.urlsafe_b64encode(hashlib.sha256(
                b'mini-keycloak/local-development/oidc-key-encryption\0' + secret).digest()).decode('ascii')
        from mini_keycloak.extensions import database_engine_options, validate_database_config
        validate_database_config(settings, config)
        config['SQLALCHEMY_ENGINE_OPTIONS'] = database_engine_options(settings, config.get('SQLALCHEMY_ENGINE_OPTIONS'))
        return config
