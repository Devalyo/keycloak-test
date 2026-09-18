import pytest
from flask import request

from mini_keycloak.app import create_app
from mini_keycloak.extensions import db
from mini_keycloak.services.bootstrap import ensure_demo_realm


FORWARDED = {
    'Forwarded': 'for=203.0.113.9;proto=https;host=evil.example',
    'X-Forwarded-For': '203.0.113.9', 'X-Forwarded-Proto': 'https',
    'X-Forwarded-Host': 'evil.example', 'X-Forwarded-Port': '444',
    'X-Forwarded-Prefix': '/evil',
}


@pytest.mark.parametrize('host, status', [
    ('localhost', 200), ('LOCALHOST', 200), ('127.0.0.1:5000', 200), ('[::1]:5000', 200),
    ('[::2]:5000', 400), ('unconfigured.example', 400),
])
def test_local_defaults_enforce_loopback_hosts(host, status):
    assert probe_app().test_client().get('/probe', headers={'Host': host}).status_code == status


def probe_app(**overrides):
    app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:', **overrides})

    @app.get('/probe')
    def probe():
        return {'scheme': request.scheme, 'remote': request.remote_addr,
                'host': request.host, 'prefix': request.script_root,
                'forwarded': {name: value for name, value in request.headers
                              if name.lower() == 'forwarded' or name.lower().startswith('x-forwarded-')}}

    return app


@pytest.mark.parametrize('config, peer', [
    ({}, '127.0.0.1'),
    ({'PROXY_MODE': 'xforwarded', 'TRUSTED_PROXY_CIDRS': ['10.20.0.0/24']}, '192.0.2.5'),
    ({'PROXY_MODE': 'xforwarded', 'TRUSTED_PROXY_CIDRS': ['10.20.0.0/24']}, 'not-an-address'),
])
def test_forwarding_is_stripped_without_a_trusted_direct_peer(config, peer):
    response = probe_app(**config).test_client().get('/probe', headers=FORWARDED,
        environ_overrides={'REMOTE_ADDR': peer})
    assert response.json == {'scheme': 'http', 'remote': peer, 'host': 'localhost',
                             'prefix': '', 'forwarded': {}}


@pytest.mark.parametrize('peer', ['10.20.0.8', '2001:db8::8'])
def test_trusted_peer_can_forward_source_and_scheme_only(peer):
    app = probe_app(PROXY_MODE='xforwarded', TRUSTED_PROXY_CIDRS=['10.20.0.0/24', '2001:db8::/64'])
    response = app.test_client().get('/probe', headers=FORWARDED,
        environ_overrides={'REMOTE_ADDR': peer})
    assert response.json == {'scheme': 'https', 'remote': '203.0.113.9',
                             'host': 'localhost', 'prefix': '', 'forwarded': {}}


def test_proxy_hops_select_from_the_right_and_ignore_short_chains():
    app = probe_app(PROXY_MODE='xforwarded', TRUSTED_PROXY_CIDRS=['10.20.0.8/32'], PROXY_HOPS=2)
    client = app.test_client()
    response = client.get('/probe', headers=FORWARDED | {
        'X-Forwarded-For': '192.0.2.99, 203.0.113.9, 10.30.0.1',
        'X-Forwarded-Proto': 'http, https, http',
    }, environ_overrides={'REMOTE_ADDR': '10.20.0.8'})
    assert response.json['remote'] == '203.0.113.9'
    assert response.json['scheme'] == 'https'
    response = client.get('/probe', headers=FORWARDED, environ_overrides={'REMOTE_ADDR': '10.20.0.8'})
    assert response.json['remote'] == '10.20.0.8'
    assert response.json['scheme'] == 'http'


@pytest.mark.parametrize('host', ['evil.example', 'sub.identity.example.test', 'identity.example.test.evil'])
def test_explicit_trusted_hosts_reject_other_hosts_even_through_trusted_proxy(host):
    app = probe_app(TRUSTED_HOSTS=['identity.example.test'], PROXY_MODE='xforwarded',
                    TRUSTED_PROXY_CIDRS=['10.20.0.8/32'])
    response = app.test_client().get('/probe', headers=FORWARDED | {
        'Host': host, 'X-Forwarded-Host': 'identity.example.test',
    }, environ_overrides={'REMOTE_ADDR': '10.20.0.8'})
    assert response.status_code == 400


def test_configured_host_and_issuer_survive_forwarded_host_and_prefix():
    app = probe_app(TRUSTED_HOSTS=['identity.example.test'], EXTERNAL_URL='https://identity.example.test/auth',
                    PROXY_MODE='xforwarded', TRUSTED_PROXY_CIDRS=['10.20.0.8/32'])
    with app.app_context():
        db.create_all()
        ensure_demo_realm(db.session)
        db.session.commit()
    response = app.test_client().get('/realms/demo/.well-known/openid-configuration',
        headers=FORWARDED | {'Host': 'identity.example.test'}, environ_overrides={'REMOTE_ADDR': '10.20.0.8'})
    assert response.status_code == 200
    assert response.json['issuer'] == 'https://identity.example.test/auth/realms/demo'
    assert 'evil.example' not in response.text and '/evil' not in response.text
