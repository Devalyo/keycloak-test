import base64

import pytest
from cryptography.fernet import InvalidToken

from mini_keycloak.app import create_app
from mini_keycloak.config import Settings
from mini_keycloak.security.key_encryption import decrypt_private_pem, encrypt_private_pem


def test_settings_default_to_local_sqlite(monkeypatch):
    monkeypatch.delenv("MINI_KEYCLOAK_DATABASE_URL", raising=False)
    monkeypatch.delenv("MINI_KEYCLOAK_EXTERNAL_URL", raising=False)
    settings = Settings.from_env()
    assert settings.database_url == "sqlite:///mini-keycloak.db"
    assert settings.external_url == "http://127.0.0.1:5000"


def test_settings_normalize_external_url(monkeypatch):
    monkeypatch.setenv("MINI_KEYCLOAK_EXTERNAL_URL", "https://id.example.test/")
    assert Settings.from_env().external_url == "https://id.example.test"


def test_flask_config_uses_supplied_database_url():
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        external_url="http://issuer.test",
        secret_key="test-only-secret",
    )
    assert settings.as_flask_config()["SQLALCHEMY_DATABASE_URI"].endswith(
        "/:memory:"
    )


LIFETIMES = {
    "access_token_lifetime_seconds": 300,
    "authorization_code_lifetime_seconds": 60,
    "refresh_token_lifetime_seconds": 1800,
    "sso_idle_lifetime_seconds": 1800,
    "sso_max_lifetime_seconds": 36000,
}


def test_oidc_defaults_are_available_to_flask(monkeypatch):
    for name in (*LIFETIMES, "session_cookie_secure", "oidc_key_encryption_secret"):
        monkeypatch.delenv("MINI_KEYCLOAK_" + name.upper(), raising=False)
    settings = Settings.from_env()
    config = settings.as_flask_config()
    for name, value in LIFETIMES.items():
        assert getattr(settings, name, None) == value
        assert config[name.upper()] == value
    assert config["SESSION_COOKIE_SECURE"] is False
    assert len(base64.urlsafe_b64decode(config["OIDC_KEY_ENCRYPTION_SECRET"])) == 32


@pytest.mark.parametrize("name", LIFETIMES)
def test_oidc_lifetimes_parse_environment_as_integers(monkeypatch, name):
    monkeypatch.setenv("MINI_KEYCLOAK_" + name.upper(), "123")
    settings = Settings.from_env()
    assert getattr(settings, name, None) == 123
    assert settings.as_flask_config()[name.upper()] == 123


@pytest.mark.parametrize("name", LIFETIMES)
@pytest.mark.parametrize("value", ["0", "-1", "1.5", "", "ten"])
def test_oidc_lifetimes_reject_invalid_environment(monkeypatch, name, value):
    variable = "MINI_KEYCLOAK_" + name.upper()
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError, match=variable):
        Settings.from_env()


@pytest.mark.parametrize("value, expected", [("true", True), ("1", True), ("false", False), ("0", False)])
def test_browser_cookie_security_is_typed(monkeypatch, value, expected):
    monkeypatch.setenv("MINI_KEYCLOAK_SESSION_COOKIE_SECURE", value)
    assert Settings.from_env().as_flask_config()["SESSION_COOKIE_SECURE"] is expected


def test_browser_cookie_security_rejects_ambiguous_value(monkeypatch):
    monkeypatch.setenv("MINI_KEYCLOAK_SESSION_COOKIE_SECURE", "maybe")
    with pytest.raises(ValueError, match="MINI_KEYCLOAK_SESSION_COOKIE_SECURE"):
        Settings.from_env()


def test_local_key_secret_is_stable_and_bound_to_application_secret():
    first = Settings(secret_key="first").as_flask_config()
    second = Settings(secret_key="first").as_flask_config()
    other = Settings(secret_key="second").as_flask_config()
    assert first["OIDC_KEY_ENCRYPTION_SECRET"] == second["OIDC_KEY_ENCRYPTION_SECRET"]
    assert first["OIDC_KEY_ENCRYPTION_SECRET"] != other["OIDC_KEY_ENCRYPTION_SECRET"]
    assert len(base64.urlsafe_b64decode(first["OIDC_KEY_ENCRYPTION_SECRET"])) == 32


def test_explicit_key_secret_is_used(monkeypatch):
    monkeypatch.setenv("MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET", "explicit-key")
    settings = Settings.from_env()
    assert getattr(settings, "oidc_key_encryption_secret", None) == "explicit-key"
    assert settings.as_flask_config()["OIDC_KEY_ENCRYPTION_SECRET"] == "explicit-key"


def test_factory_fallback_uses_final_application_secret(monkeypatch):
    monkeypatch.delenv('MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET', raising=False)
    monkeypatch.setenv('MINI_KEYCLOAK_SECRET_KEY', 'environment-application-secret')
    configs = [create_app({'SECRET_KEY': secret}).config
               for secret in ('first-injected-secret', 'first-injected-secret', 'other-injected-secret')]
    first, repeated, other = [config['OIDC_KEY_ENCRYPTION_SECRET'] for config in configs]
    assert first == repeated
    assert first != other
    assert first == Settings(secret_key='first-injected-secret').as_flask_config()['OIDC_KEY_ENCRYPTION_SECRET']
    encrypted = encrypt_private_pem(b'private-key-fixture', first)
    assert decrypt_private_pem(encrypted, repeated) == b'private-key-fixture'
    with pytest.raises(InvalidToken):
        decrypt_private_pem(encrypted, other)
    with pytest.raises(InvalidToken):
        decrypt_private_pem(encrypted, Settings.from_env().as_flask_config()['OIDC_KEY_ENCRYPTION_SECRET'])


@pytest.mark.parametrize('environment, explicit, expected', [
    ('environment-master', {}, 'environment-master'),
    ('environment-master', {'OIDC_KEY_ENCRYPTION_SECRET': 'passed-master'}, 'passed-master'),
    (None, {'OIDC_KEY_ENCRYPTION_SECRET': 'passed-master'}, 'passed-master'),
    ('', {'OIDC_KEY_ENCRYPTION_SECRET': 'passed-master'}, 'passed-master'),
])
def test_factory_explicit_master_secret_precedence(monkeypatch, environment, explicit, expected):
    if environment is None:
        monkeypatch.delenv('MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET', raising=False)
    else:
        monkeypatch.setenv('MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET', environment)
    app = create_app({'SECRET_KEY': 'passed-application-secret'} | explicit)
    assert app.config['OIDC_KEY_ENCRYPTION_SECRET'] == expected


@pytest.mark.parametrize('value', ['', None, '   '])
def test_factory_rejects_empty_explicit_master_secret(monkeypatch, value):
    monkeypatch.setenv('MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET', 'environment-master')
    with pytest.raises(ValueError, match='OIDC_KEY_ENCRYPTION_SECRET'):
        create_app({'OIDC_KEY_ENCRYPTION_SECRET': value})


def test_factory_rejects_empty_environment_master_secret(monkeypatch):
    monkeypatch.setenv('MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET', '')
    with pytest.raises(ValueError, match='OIDC_KEY_ENCRYPTION_SECRET'):
        create_app({'SECRET_KEY': 'passed-application-secret'})


@pytest.mark.parametrize('value', ['', None, b''])
def test_factory_rejects_empty_application_secret_for_fallback(monkeypatch, value):
    monkeypatch.delenv('MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET', raising=False)
    with pytest.raises(ValueError, match='SECRET_KEY'):
        create_app({'SECRET_KEY': value})


@pytest.fixture
def production_env(monkeypatch):
    values = {
        'PROFILE': 'production',
        'DATABASE_URL': 'postgresql+psycopg://operator:database-password@db:5432/identity',
        'EXTERNAL_URL': 'https://identity.example.test',
        'SECRET_KEY': 'application-secret-' + 'a' * 32,
        'OIDC_KEY_ENCRYPTION_SECRET': 'encryption-secret-' + 'b' * 32,
        'SESSION_COOKIE_SECURE': 'true',
        'TRUSTED_HOSTS': 'identity.example.test,localhost',
        'PROXY_MODE': 'none',
    }
    for name, value in values.items():
        monkeypatch.setenv('MINI_KEYCLOAK_' + name, value)
    return values


@pytest.mark.parametrize('value', ['', 'Production', 'staging', 'private-sentinel'])
def test_profile_rejects_unknown_names_without_values(monkeypatch, value):
    monkeypatch.setenv('MINI_KEYCLOAK_PROFILE', value)
    with pytest.raises(ValueError) as error:
        Settings.from_env()
    assert str(error.value) == 'MINI_KEYCLOAK_PROFILE'


def test_production_settings_are_complete_and_do_not_need_a_driver(production_env):
    config = Settings.from_env().as_flask_config()
    assert config['PROFILE'] == 'production'
    assert config['TRUSTED_HOSTS'] == ['identity.example.test', 'localhost']
    assert config['SESSION_COOKIE_SECURE'] is True
    assert config['OIDC_KEY_ENCRYPTION_SECRET'] == production_env['OIDC_KEY_ENCRYPTION_SECRET']
    assert config['SQLALCHEMY_ENGINE_OPTIONS']['pool_pre_ping'] is True


@pytest.mark.parametrize('name', [
    'DATABASE_URL', 'EXTERNAL_URL', 'SECRET_KEY', 'OIDC_KEY_ENCRYPTION_SECRET',
    'SESSION_COOKIE_SECURE', 'TRUSTED_HOSTS', 'PROXY_MODE',
])
def test_production_rejects_missing_requirements(production_env, monkeypatch, name):
    monkeypatch.delenv('MINI_KEYCLOAK_' + name)
    with pytest.raises(ValueError) as error:
        Settings.from_env()
    assert str(error.value) == 'MINI_KEYCLOAK_' + name


@pytest.mark.parametrize('name, value', [
    ('DATABASE_URL', ''), ('DATABASE_URL', 'sqlite:///:memory:'),
    ('DATABASE_URL', 'postgresql://db/identity'),
    ('DATABASE_URL', 'postgresql+psycopg:///identity'),
    ('DATABASE_URL', 'postgresql+psycopg://db:0/identity'),
    ('DATABASE_URL', 'postgresql+psycopg://db:65536/identity'),
    ('DATABASE_URL', 'postgresql+psycopg://db:/identity'),
    ('DATABASE_URL', 'postgresql+psycopg://db/'),
    ('EXTERNAL_URL', ''), ('EXTERNAL_URL', '//identity.example.test'),
    ('EXTERNAL_URL', 'http://identity.example.test'),
    ('EXTERNAL_URL', 'https://user:private-sentinel@identity.example.test'),
    ('EXTERNAL_URL', 'https://identity.example.test?private-sentinel'),
    ('EXTERNAL_URL', 'https://identity.example.test#private-sentinel'),
    ('EXTERNAL_URL', 'https://identity.example.test?'),
    ('EXTERNAL_URL', 'https://identity.example.test#'),
    ('EXTERNAL_URL', 'https://identity.example.test:0'),
    ('EXTERNAL_URL', 'https://identity.example.test:65536'),
    ('EXTERNAL_URL', 'https://identity.example.test:'),
    ('EXTERNAL_URL', 'https://identity.example.test\n'),
    ('EXTERNAL_URL', 'https://identity.example.test\\evil'),
    ('EXTERNAL_URL', 'https://identity.example.test//ambiguous'),
    ('EXTERNAL_URL', 'https://identity.example.test/../ambiguous'),
    ('EXTERNAL_URL', 'https://identity.example.test/%2e%2e'),
    ('SECRET_KEY', 'local-development-secret-change-me'),
    ('SECRET_KEY', 'a' * 31), ('SECRET_KEY', ' ' * 32),
    ('OIDC_KEY_ENCRYPTION_SECRET', ''),
    ('OIDC_KEY_ENCRYPTION_SECRET', 'b' * 31),
    ('SESSION_COOKIE_SECURE', 'false'),
    ('TRUSTED_HOSTS', ''), ('TRUSTED_HOSTS', '*'),
    ('TRUSTED_HOSTS', '.example.test'), ('TRUSTED_HOSTS', '*.example.test'),
    ('TRUSTED_HOSTS', 'other.example.test'),
    ('TRUSTED_HOSTS', 'identity.example.test,'),
    ('TRUSTED_HOSTS', 'https://identity.example.test'),
    ('TRUSTED_HOSTS', 'identity.example.test:443'),
    ('PROXY_MODE', ''), ('PROXY_MODE', 'forwarded'),
])
def test_production_rejects_unsafe_values_without_disclosing_them(
        production_env, monkeypatch, name, value):
    monkeypatch.setenv('MINI_KEYCLOAK_' + name, value)
    with pytest.raises(ValueError) as error:
        Settings.from_env()
    assert str(error.value) == 'MINI_KEYCLOAK_' + name


def test_production_requires_independent_secrets(production_env, monkeypatch):
    monkeypatch.setenv('MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET', production_env['SECRET_KEY'])
    with pytest.raises(ValueError, match='^MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET$'):
        Settings.from_env()


def test_production_normalizes_fixed_external_url(production_env, monkeypatch):
    monkeypatch.setenv('MINI_KEYCLOAK_EXTERNAL_URL', 'https://IDENTITY.example.test:443/')
    assert Settings.from_env().external_url == 'https://identity.example.test'


@pytest.mark.parametrize('path', ['/auth', '/auth/', '/nested/auth'])
def test_production_rejects_unserved_external_path_prefixes(production_env, monkeypatch, path):
    from mini_keycloak.extensions import db

    def forbidden_initialization(*args, **kwargs):
        pytest.fail('extension initialized before unsupported external path was rejected')

    monkeypatch.setattr(db, 'init_app', forbidden_initialization)
    with pytest.raises(ValueError, match='^MINI_KEYCLOAK_EXTERNAL_URL$'):
        create_app({'EXTERNAL_URL': 'https://identity.example.test' + path})


def test_local_external_path_is_metadata_only_and_does_not_mount_routes():
    from mini_keycloak.extensions import db
    from mini_keycloak.services.bootstrap import ensure_demo_realm
    from urllib.parse import urlsplit

    app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
                      'EXTERNAL_URL': 'http://localhost/auth'})
    with app.app_context():
        db.create_all()
        ensure_demo_realm(db.session)
        db.session.commit()
    browser = app.test_client()
    metadata = browser.get('/realms/demo/.well-known/openid-configuration').json
    assert metadata['issuer'] == 'http://localhost/auth/realms/demo'
    # Historical local prefix metadata is retained; there is no prefix mounting.
    assert browser.get(urlsplit(metadata['jwks_uri']).path).status_code == 404


@pytest.mark.parametrize('name', [
    'DATABASE_POOL_SIZE', 'DATABASE_MAX_OVERFLOW', 'DATABASE_POOL_TIMEOUT_SECONDS',
    'DATABASE_POOL_RECYCLE_SECONDS', *[name.upper() for name in LIFETIMES],
])
@pytest.mark.parametrize('value', ['0', '-1', '1.5', 'private-sentinel', '', '1_000', ' 1'])
def test_numeric_settings_reject_malformed_values_without_echo(monkeypatch, name, value):
    monkeypatch.setenv('MINI_KEYCLOAK_' + name, value)
    with pytest.raises(ValueError) as error:
        Settings.from_env()
    assert str(error.value) == 'MINI_KEYCLOAK_' + name


@pytest.mark.parametrize('name, value', [
    ('LOG_LEVEL', 'private-sentinel'), ('LOG_LEVEL', 'NOTSET'),
    ('PROXY_HOPS', '0'), ('PROXY_HOPS', '9'), ('PROXY_HOPS', '1.5'),
    ('TRUSTED_PROXY_CIDRS', '*'), ('TRUSTED_PROXY_CIDRS', 'not-a-cidr'),
    ('TRUSTED_PROXY_CIDRS', '10.0.0.0/33'),
    ('TRUSTED_PROXY_CIDRS', '10.0.0.0/24,'),
])
def test_log_and_proxy_settings_are_bounded(monkeypatch, name, value):
    monkeypatch.setenv('MINI_KEYCLOAK_' + name, value)
    with pytest.raises(ValueError) as error:
        Settings.from_env()
    assert str(error.value) == 'MINI_KEYCLOAK_' + name


def test_forwarding_requires_explicit_direct_peer_networks(monkeypatch):
    monkeypatch.setenv('MINI_KEYCLOAK_PROXY_MODE', 'xforwarded')
    with pytest.raises(ValueError, match='^MINI_KEYCLOAK_TRUSTED_PROXY_CIDRS$'):
        Settings.from_env()


def test_database_pool_settings_apply_only_to_postgresql(monkeypatch):
    for name, value in {'SIZE': '3', 'TIMEOUT_SECONDS': '7', 'RECYCLE_SECONDS': '90'}.items():
        monkeypatch.setenv('MINI_KEYCLOAK_DATABASE_POOL_' + name, value)
    monkeypatch.setenv('MINI_KEYCLOAK_DATABASE_MAX_OVERFLOW', '4')
    monkeypatch.setenv('MINI_KEYCLOAK_DATABASE_URL', 'postgresql+psycopg://db/identity')
    assert Settings.from_env().as_flask_config()['SQLALCHEMY_ENGINE_OPTIONS'] == {
        'pool_pre_ping': True, 'pool_size': 3, 'max_overflow': 4,
        'pool_timeout': 7, 'pool_recycle': 90,
    }
    app = create_app({'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'})
    assert app.config['SQLALCHEMY_ENGINE_OPTIONS'] == {}
    from mini_keycloak.extensions import db
    from sqlalchemy import text
    with app.app_context():
        assert db.session.scalar(text('PRAGMA foreign_keys')) == 1


@pytest.mark.parametrize('override, name', [
    ({'PROFILE': 'local'}, 'PROFILE'),
    ({'SECRET_KEY': 'short'}, 'SECRET_KEY'),
    ({'OIDC_KEY_ENCRYPTION_SECRET': None}, 'OIDC_KEY_ENCRYPTION_SECRET'),
    ({'SESSION_COOKIE_SECURE': False}, 'SESSION_COOKIE_SECURE'),
    ({'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'}, 'DATABASE_URL'),
    ({'EXTERNAL_URL': 'http://identity.example.test'}, 'EXTERNAL_URL'),
    ({'TRUSTED_HOSTS': ['*']}, 'TRUSTED_HOSTS'),
    ({'ACCESS_TOKEN_LIFETIME_SECONDS': True}, 'ACCESS_TOKEN_LIFETIME_SECONDS'),
    ({'SQLALCHEMY_ENGINE_OPTIONS': {'pool_pre_ping': False}}, 'SQLALCHEMY_ENGINE_OPTIONS'),
])
def test_factory_validates_final_production_values_before_extensions(
        production_env, monkeypatch, override, name):
    from mini_keycloak.extensions import db

    def forbidden_initialization(*args, **kwargs):
        pytest.fail('extension initialized before invalid settings were rejected')

    monkeypatch.setattr(db, 'init_app', forbidden_initialization)
    with pytest.raises(ValueError, match='^MINI_KEYCLOAK_' + name + '$'):
        create_app(override)


def test_factory_can_supply_required_production_values(production_env, monkeypatch):
    monkeypatch.delenv('MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET')
    settings = Settings.from_env(overrides={
        'OIDC_KEY_ENCRYPTION_SECRET': 'factory-encryption-' + 'c' * 32,
    })
    assert settings.as_flask_config()['OIDC_KEY_ENCRYPTION_SECRET'] == 'factory-encryption-' + 'c' * 32


def test_local_default_hosts_include_only_loopback_and_configured_external_host(monkeypatch):
    monkeypatch.setenv('MINI_KEYCLOAK_EXTERNAL_URL', 'http://issuer.test:5000')
    assert Settings.from_env().as_flask_config()['TRUSTED_HOSTS'] == [
        'localhost', '127.0.0.1', '[::1]', 'issuer.test',
    ]


def test_factory_preserves_non_boundary_options():
    config = Settings().as_flask_config(overrides={
        'TESTING': True, 'SQLALCHEMY_TRACK_MODIFICATIONS': True,
        'SQLALCHEMY_ENGINE_OPTIONS': {'connect_args': {'timeout': 2}},
    })
    assert config['TESTING'] is True
    assert config['SQLALCHEMY_TRACK_MODIFICATIONS'] is True
    assert config['SQLALCHEMY_ENGINE_OPTIONS'] == {'connect_args': {'timeout': 2}}


@pytest.mark.parametrize('options', [
    {'isolation_level': 'AUTOCOMMIT'}, {'isolation_level': 'READ COMMITTED'},
    {'execution_options': {'isolation_level': 'AUTOCOMMIT'}},
    {'execution_options': {'autocommit': True}},
    {'connect_args': {'host': 'private-sentinel', 'dbname': 'replacement'}},
    {'connect_args': {'sslmode': 'verify-full'}},
    {'creator': lambda: None}, {'poolclass': object}, {'pool': object()},
    {'pool_reset_on_return': None}, {'echo': True}, {'echo': 'debug'},
    {'echo_pool': 'debug'}, {'url': 'sqlite:///:memory:'},
    {'unknown': 'private-sentinel'}, {'pool_pre_ping': 1},
])
def test_production_rejects_alternate_engine_controls_before_extensions(production_env, monkeypatch, options):
    from mini_keycloak.extensions import db

    def forbidden_initialization(*args, **kwargs):
        pytest.fail('extension initialized before unsupported options were rejected')

    monkeypatch.setattr(db, 'init_app', forbidden_initialization)
    with pytest.raises(ValueError, match='^MINI_KEYCLOAK_SQLALCHEMY_ENGINE_OPTIONS$'):
        create_app({'SQLALCHEMY_ENGINE_OPTIONS': options})


@pytest.mark.parametrize('field, value', [
    ('SQLALCHEMY_BINDS', {'other': 'sqlite:///:memory:'}),
    ('SQLALCHEMY_BINDS', {None: {'isolation_level': 'AUTOCOMMIT'}}),
    ('SQLALCHEMY_BINDS', None), ('SQLALCHEMY_BINDS', []),
    ('SQLALCHEMY_ECHO', True), ('SQLALCHEMY_ECHO', 'debug'), ('SQLALCHEMY_ECHO', 'false'),
    ('SQLALCHEMY_RECORD_QUERIES', True), ('SQLALCHEMY_RECORD_QUERIES', 'false'),
    ('SQLALCHEMY_TRACK_MODIFICATIONS', True),
    ('SQLALCHEMY_POOL_SIZE', 10), ('SQLALCHEMY_UNKNOWN', 'private-sentinel'),
])
def test_production_rejects_other_database_config_entry_points(production_env, monkeypatch, field, value):
    from mini_keycloak.extensions import db

    def forbidden_initialization(*args, **kwargs):
        pytest.fail('extension initialized before unsupported database entry point was rejected')

    monkeypatch.setattr(db, 'init_app', forbidden_initialization)
    with pytest.raises(ValueError, match='^MINI_KEYCLOAK_' + field + '$'):
        create_app({field: value})


def test_production_accepts_only_matching_typed_engine_options_and_disabled_logging(production_env):
    config = Settings.from_env().as_flask_config(overrides={
        'SQLALCHEMY_ENGINE_OPTIONS': {'pool_pre_ping': True, 'pool_size': 5,
            'max_overflow': 10, 'pool_timeout': 30, 'pool_recycle': 1800},
        'SQLALCHEMY_BINDS': {}, 'SQLALCHEMY_ECHO': False,
        'SQLALCHEMY_RECORD_QUERIES': False, 'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    })
    assert config['SQLALCHEMY_ENGINE_OPTIONS'] == {
        'pool_pre_ping': True, 'pool_size': 5, 'max_overflow': 10, 'pool_timeout': 30, 'pool_recycle': 1800,
    }
    assert config['SQLALCHEMY_ECHO'] is False
    assert config['SQLALCHEMY_RECORD_QUERIES'] is False
    assert config['SQLALCHEMY_BINDS'] == {}


def test_local_database_overrides_remain_available(monkeypatch):
    from mini_keycloak.extensions import db
    from sqlalchemy import text

    # Flask-SQLAlchemy retains bind metadata across app factories; isolate this
    # test's extra bind so later default-only fixtures can create their schema.
    monkeypatch.setattr(db, 'metadatas', db.metadatas.copy())
    app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_ENGINE_OPTIONS': {'connect_args': {'timeout': 2}, 'isolation_level': 'SERIALIZABLE'},
        'SQLALCHEMY_BINDS': {'other': 'sqlite:///:memory:'},
        'SQLALCHEMY_ECHO': False, 'SQLALCHEMY_RECORD_QUERIES': True})
    with app.app_context():
        assert db.session.scalar(text('SELECT 1')) == 1
        assert set(db.engines) == {None, 'other'}


@pytest.mark.parametrize('query, expected', [
    ('sslmode=require', {'sslmode': 'require'}),
    ('connect_timeout=1', {'connect_timeout': '1'}),
    ('connect_timeout=60', {'connect_timeout': '60'}),
    ('sslmode=require&connect_timeout=5', {'sslmode': 'require', 'connect_timeout': '5'}),
    ('sslmode=verify-ca&sslrootcert=%2Fetc%2Fcerts%2Froot.pem',
     {'sslmode': 'verify-ca', 'sslrootcert': '/etc/certs/root.pem'}),
    ('sslmode=verify-full&sslrootcert=/etc/certs/root.pem&connect_timeout=5',
     {'sslmode': 'verify-full', 'sslrootcert': '/etc/certs/root.pem', 'connect_timeout': '5'}),
    ('sslmode=verify-full&sslrootcert=/etc/CA%20Certs/root.pem',
     {'sslmode': 'verify-full', 'sslrootcert': '/etc/CA Certs/root.pem'}),
])
def test_production_database_tls_and_timeout_options_reach_the_driver_without_connecting(
        production_env, monkeypatch, query, expected):
    from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg
    from sqlalchemy.engine import make_url

    monkeypatch.setenv('MINI_KEYCLOAK_DATABASE_URL', production_env['DATABASE_URL'] + '?' + query)
    config = Settings.from_env().as_flask_config()
    args, parameters = PGDialect_psycopg().create_connect_args(make_url(config['SQLALCHEMY_DATABASE_URI']))
    assert not args
    assert parameters['host'] == 'db' and parameters['dbname'] == 'identity'
    assert {name: parameters[name] for name in expected} == expected
    assert config['SQLALCHEMY_ENGINE_OPTIONS']['pool_pre_ping'] is True


@pytest.mark.parametrize('query', [
    '', 'sslmode', 'sslmode=', 'sslmode=disable', 'sslmode=allow', 'sslmode=prefer',
    'sslmode=REQUIRE', 'sslmode=verify-ca', 'sslmode=verify-full',
    'sslrootcert=/etc/ca.pem', 'sslmode=require&sslrootcert=/etc/ca.pem',
    'sslmode=verify-full&sslrootcert=relative.pem',
    'sslmode=verify-full&sslrootcert=~/ca.pem',
    'sslmode=verify-full&sslrootcert=/',
    'sslmode=verify-full&sslrootcert=/etc/../ca.pem',
    'sslmode=verify-full&sslrootcert=/etc/./ca.pem',
    'sslmode=verify-full&sslrootcert=//etc/ca.pem',
    'sslmode=verify-full&sslrootcert=/etc/ca.pem/',
    'sslmode=verify-full&sslrootcert=/etc/ca.pem%00private-sentinel',
    'sslmode=verify-full&sslrootcert=/etc/ca.pem%0Aprivate-sentinel',
    'sslmode=verify-full&sslrootcert=/etc/ca.pem%7F',
    'sslmode=verify-full&sslrootcert=/etc/ca.pem%C2%85',
    'sslmode=verify-full&sslrootcert=/etc/ca.pem%E2%80%AE',
    'sslmode=verify-full&sslrootcert=/etc/ca%5Cname.pem',
    'sslmode=verify-full&sslrootcert=/etc/%252e%252e/ca.pem',
    'sslmode=verify-full&sslrootcert=/etc/%ZZ/ca.pem',
    'sslmode=verify-full&sslrootcert=/etc/ca.pem%20',
    'sslmode=verify-full&sslrootcert=/etc/' + 'a' * 4096,
    'connect_timeout=0', 'connect_timeout=-1', 'connect_timeout=61', 'connect_timeout=01',
    'connect_timeout=1.5', 'connect_timeout=+5', 'connect_timeout=%205',
    'connect_timeout=1_0', 'connect_timeout=private-sentinel',
    'host=private-sentinel', 'hostaddr=127.0.0.1', 'dbname=private-sentinel',
    'user=private-sentinel', 'password=private-sentinel', 'port=6543',
    'options=-c%20default_transaction_read_only%3Doff', 'isolation_level=AUTOCOMMIT',
    'autocommit=true', 'echo=debug', 'service=private-sentinel',
    'sslmode=require&unknown=', 'sslmode=require&',
    'sslmode=require;connect_timeout=5',
    'sslmode=require&%73slmode=verify-full',
])
def test_production_database_options_reject_unsafe_or_ambiguous_values_before_extensions(
        production_env, monkeypatch, query):
    from mini_keycloak.extensions import db

    def forbidden_initialization(*args, **kwargs):
        pytest.fail('extension initialized before invalid database query was rejected')

    monkeypatch.setattr(db, 'init_app', forbidden_initialization)
    with pytest.raises(ValueError, match='^MINI_KEYCLOAK_DATABASE_URL$'):
        create_app({'SQLALCHEMY_DATABASE_URI': production_env['DATABASE_URL'] + '?' + query})


@pytest.mark.parametrize('field, values', [
    ('sslmode', ('require', 'require')), ('sslmode', ('require', 'verify-full')),
    ('connect_timeout', ('5', '5')), ('sslrootcert', ('/etc/first.pem', '/etc/second.pem')),
])
def test_production_rejects_sqlalchemy_tuple_values_from_duplicate_query_keys(
        production_env, monkeypatch, field, values):
    from sqlalchemy.engine import make_url

    url = production_env['DATABASE_URL'] + '?' + '&'.join(field + '=' + value for value in values)
    # SQLAlchemy preserves repeated values as tuples; never silently pick one.
    assert make_url(url).query[field] == values
    monkeypatch.setenv('MINI_KEYCLOAK_DATABASE_URL', url)
    with pytest.raises(ValueError, match='^MINI_KEYCLOAK_DATABASE_URL$'):
        Settings.from_env()
