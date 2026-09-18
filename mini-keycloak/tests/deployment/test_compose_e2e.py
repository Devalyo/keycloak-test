"""Run only a unique, temporary local project; never call the reset/Demo paths."""

import base64
import hashlib
from http.cookiejar import CookieJar
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import (build_opener, HTTPCookieProcessor, HTTPRedirectHandler,
                            HTTPSHandler, ProxyHandler, Request)

import jwt
import pytest

from tests.helpers import form_action


ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.deployment


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Stack:
    def __init__(self):
        self.project = 'mk-e2e-' + secrets.token_hex(12)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        self.origin = f'https://localhost:{self.port}'
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('MINI_KEYCLOAK_', 'POSTGRES_', 'COMPOSE_'))}
        self.sensitive = [secrets.token_hex(32) for _ in range(3)]
        self.env.update(zip(('POSTGRES_PASSWORD', 'MINI_KEYCLOAK_SECRET_KEY',
                             'MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET'), self.sensitive))
        self.env['MINI_KEYCLOAK_HTTPS_PORT'] = str(self.port)
        self.command = ['docker', 'compose', '--ansi', 'never', '--env-file', os.devnull,
                        '--project-name', self.project, '--file', str(ROOT / 'compose.yaml')]
        # Allow concurrent environment projects without overlapping the shipped default subnet.
        networks = self.docker('network', 'ls', '-q').split()
        used = [ipaddress.ip_network(config['Subnet'])
                for network in json.loads(self.docker('network', 'inspect', *networks))
                for config in (network['IPAM']['Config'] or []) if config.get('Subnet')]
        for _ in range(100):
            subnet = ipaddress.ip_network(f'10.{180 + secrets.randbelow(50)}.{secrets.randbelow(256)}.0/24')
            if not any(subnet.overlaps(network) for network in used if network.version == 4):
                self.env['MINI_KEYCLOAK_PROXY_SUBNET'] = str(subnet)
                self.env['MINI_KEYCLOAK_PROXY_ADDRESS'] = str(subnet.network_address + 254)
                break
        else:
            pytest.fail('Could not allocate an isolated test subnet', pytrace=False)

    def run(self, command, *, timeout=180):
        __tracebackhide__ = True
        try:
            result = subprocess.run(command, cwd=ROOT, env=self.env, capture_output=True,
                                    text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            pytest.fail('Bounded Docker command timed out', pytrace=False)
        if result.returncode:
            output = result.stdout + result.stderr
            for value in self.sensitive:
                output = output.replace(value, '[REDACTED]')
            pytest.fail('Docker command failed: ' + output[-5000:], pytrace=False)
        return result.stdout

    def docker(self, *args, **kwargs):
        return self.run(['docker', *args], **kwargs)

    def compose(self, *args, **kwargs):
        return self.run([*self.command, *args], **kwargs)

    def state(self, service):
        container = self.compose('ps', '--all', '--quiet', service).strip()
        assert container, f'Missing {service} container'
        return json.loads(self.docker('inspect', container))[0]

    def healthy(self):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if self.state('web')['State'].get('Health', {}).get('Status') == 'healthy':
                return
            time.sleep(1)
        pytest.fail('Web did not become healthy within 90 seconds', pytrace=False)

    def request(self, path, *, data=None, headers=None):
        url = urljoin(self.origin, path)
        assert url.startswith(self.origin + '/'), 'Never follow a client redirect'
        body = urlencode(data).encode() if data is not None else None
        req = Request(url, data=body, headers=headers or {})
        try:
            response = self.http.open(req, timeout=10)
        except HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read()

    def document(self, path, **kwargs):
        status, headers, body = self.request(path, **kwargs)
        assert status == 200
        assert re.fullmatch('[a-f0-9]{32}', headers['X-Request-ID'])
        return json.loads(body)

    def assert_redacted(self, logs):
        __tracebackhide__ = True
        if any(value in logs for value in self.sensitive):
            pytest.fail('A sensitive value appeared in service logs', pytrace=False)


@pytest.fixture
def stack(tmp_path):
    if shutil.which('docker') is None:
        pytest.skip('Docker is unavailable')
    try:
        result = subprocess.run(['docker', 'info'], capture_output=True, timeout=15)
    except subprocess.TimeoutExpired:
        pytest.skip('Docker daemon is unavailable')
    if result.returncode:
        pytest.skip('Docker daemon is unavailable')
    assert (ROOT / 'compose.yaml').is_file(), 'Missing Compose deployment'
    instance = Stack()
    label = f'com.docker.compose.project={instance.project}'
    assert not instance.docker('volume', 'ls', '--filter', f'label={label}', '-q').strip()
    try:
        instance.compose('config', '--quiet')
        instance.compose('build', 'web', timeout=600)
        instance.compose('up', '-d', '--wait', 'postgres', timeout=180)
        # A fresh database cannot be ready. Factory/startup must not provision it.
        before = instance.compose('run', '--rm', '--no-deps', 'web', 'python', '-c',
            "from mini_keycloak.app import create_app; "
            "response=create_app().test_client().get('/health/ready', base_url='https://localhost'); "
            "print(response.status_code)")
        assert before.strip() == '503'
        instance.compose('up', '-d', 'caddy', timeout=240)
        instance.healthy()
        ca = tmp_path / 'gateway-root.crt'
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            check = instance.compose('exec', '-T', 'caddy', 'sh', '-c',
                'test -f /data/caddy/pki/authorities/local/root.crt && echo ready || true')
            if check.strip() == 'ready':
                break
            time.sleep(0.5)
        instance.compose('cp', 'caddy:/data/caddy/pki/authorities/local/root.crt', str(ca))
        context = ssl.create_default_context(cafile=str(ca))
        instance.cookies = CookieJar()
        instance.http = build_opener(ProxyHandler({}), HTTPSHandler(context=context),
                                     HTTPCookieProcessor(instance.cookies), NoRedirect())
        yield instance
    finally:
        # Do not print captured logs; even a failing redaction assertion must stay secret-safe.
        try:
            instance.logs = instance.compose('logs', '--no-color', '--no-log-prefix', timeout=30)
        finally:
            instance.compose('down', '--volumes', '--remove-orphans', '--timeout', '20', timeout=120)
        for resource, args in [('container', ('ps', '-aq')), ('volume', ('volume', 'ls', '-q')),
                               ('network', ('network', 'ls', '-q'))]:
            remaining = instance.docker(*args, '--filter', f'label={label}').strip()
            assert not remaining, f'Test {resource} resources were not removed'
        image = instance.project + '-app:local'
        if instance.docker('image', 'ls', '--filter', f'reference={image}', '-q').strip():
            instance.docker('image', 'rm', image)


def test_fresh_compose_tls_oidc_persistence_and_secret_safe_logs(stack):
    issuer = stack.origin + '/realms/demo'
    discovery_path = '/realms/demo/.well-known/openid-configuration'
    protocol = '/realms/demo/protocol/openid-connect/'
    statuses = {name: stack.state(name) for name in ('postgres', 'migrate', 'bootstrap', 'web', 'caddy')}
    for name in ('migrate', 'bootstrap'):
        assert statuses[name]['State']['Status'] == 'exited'
        assert statuses[name]['State']['ExitCode'] == 0
        assert statuses[name]['RestartCount'] == 0
    assert statuses['migrate']['State']['FinishedAt'] < statuses['bootstrap']['State']['StartedAt']
    assert statuses['bootstrap']['State']['FinishedAt'] < statuses['web']['State']['StartedAt']
    assert statuses['web']['State']['Health']['Status'] == 'healthy'
    for name in ('postgres', 'web'):
        assert not statuses[name]['HostConfig']['PortBindings']
    assert statuses['caddy']['HostConfig']['PortBindings'] == {
        '443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(stack.port)}]}
    assert statuses['web']['HostConfig']['ReadonlyRootfs'] is True
    assert statuses['web']['Config']['User'] == '10001:10001'

    # Runtime package/install proof, including operator-only migration assets.
    runtime = stack.compose('exec', '-T', 'web', 'python', '-c',
        "import importlib.resources, json, os, pathlib, shutil; "
        "fixture=importlib.resources.files('mini_keycloak').joinpath('import_export/fixtures/demo-realm.json'); "
        "print(json.dumps(dict(uid=os.getuid(), fixture=fixture.is_file(), "
        "migrations=len(list(pathlib.Path('/app/migrations/versions').glob('*.py'))), "
        "compiler=any(shutil.which(x) for x in ['cc','gcc','clang']), "
        "source=any(pathlib.Path(x).exists() for x in ['/app/tests','/app/mini_keycloak','/build','/wheels']), "
        "cache=pathlib.Path('/root/.cache/pip').exists())))")
    assert json.loads(runtime) == dict(uid=10001, fixture=True, migrations=6,
                                      compiler=False, source=False, cache=False)
    stack.compose('exec', '-T', 'web', 'python', '-m', 'pip', 'check')
    for health in ('/health', '/health/', '/health/live', '/health/ready'):
        status, headers, body = stack.request(health)
        assert (status, body) == (404, b'Not found')
        assert 'X-Request-ID' not in headers

    # A system-trust-only client rejects this fresh project's private CA.
    untrusted = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()))
    with pytest.raises(URLError) as error:
        untrusted.open(stack.origin + discovery_path, timeout=10)
    assert isinstance(error.value.reason, ssl.SSLCertVerificationError)

    discovery = stack.document(discovery_path)
    assert discovery['issuer'] == issuer
    for field in ('authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'end_session_endpoint'):
        assert discovery[field].startswith(issuer + '/protocol/openid-connect/')
    jwks = stack.document(protocol + 'certs')['keys']
    assert len(jwks) == 1
    old_kid = jwks[0]['kid']
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    nonce, state = secrets.token_hex(16), secrets.token_hex(16)
    stack.sensitive.extend([verifier, nonce, state])
    params = dict(client_id='demo-app', redirect_uri='http://localhost:9999/callback',
                  response_type='code', scope='openid profile email', state=state, nonce=nonce,
                  code_challenge=challenge, code_challenge_method='S256')
    status, _, page = stack.request(protocol + 'auth?' + urlencode(params))
    assert status == 200
    action = form_action(page.decode(), 'login-actions/authenticate')
    stack.sensitive.append(parse_qs(urlsplit(action).query)['tab_id'][0])
    status, headers, _ = stack.request(action, data={'username': 'demo-user', 'password': 'DemoPassw0rd!'})
    assert status == 302
    assert 'Secure' in headers['Set-Cookie'] and 'HttpOnly' in headers['Set-Cookie']
    location = headers['Location']
    returned = parse_qs(urlsplit(location).query)
    assert returned['state'] == [state]
    code = returned['code'][0]
    stack.sensitive.extend([code, location, headers['Set-Cookie']])
    tokens = stack.document(protocol + 'token', data=dict(grant_type='authorization_code',
        client_id='demo-app', redirect_uri=params['redirect_uri'], code=code, code_verifier=verifier))
    stack.sensitive.extend(tokens[kind] for kind in ('access_token', 'refresh_token', 'id_token'))
    claims = {}
    for kind, typ in [('access_token', 'Bearer'), ('refresh_token', 'Refresh'), ('id_token', 'ID')]:
        assert jwt.get_unverified_header(tokens[kind])['kid'] == old_kid
        claims[kind] = jwt.decode(tokens[kind], jwt.PyJWK.from_dict(jwks[0]).key,
                                  algorithms=['RS256'], audience='demo-app', issuer=issuer)
        assert claims[kind]['typ'] == typ
        assert claims[kind]['azp'] == 'demo-app'
        assert claims[kind]['sid'] == tokens['session_state']
        assert claims[kind]['preferred_username'] == 'demo-user'
    assert claims['id_token']['nonce'] == nonce
    subject = claims['access_token']['sub']
    assert stack.document(protocol + 'userinfo', headers={'Authorization': 'Bearer ' + tokens['access_token']})['sub'] == subject

    stack.compose('exec', '-T', 'web', 'flask', '--app', 'mini_keycloak.app:create_app', 'realm-key-rotate', '--realm', 'demo')
    rotated = stack.document(protocol + 'certs')['keys']
    assert len(rotated) == 2
    assert old_kid in {key['kid'] for key in rotated}
    new_key = next(key for key in rotated if key['kid'] != old_kid)
    assert all(set(key) == {'kid', 'kty', 'alg', 'use', 'n', 'e'} for key in rotated)
    fresh = stack.document(protocol + 'token', data=dict(grant_type='refresh_token',
        client_id='demo-app', refresh_token=tokens['refresh_token']))
    stack.sensitive.extend(fresh[kind] for kind in ('access_token', 'refresh_token', 'id_token'))
    assert fresh['session_state'] == tokens['session_state']
    for kind in ('access_token', 'refresh_token', 'id_token'):
        assert jwt.get_unverified_header(fresh[kind])['kid'] == new_key['kid']
        assert jwt.decode(fresh[kind], jwt.PyJWK.from_dict(new_key).key,
            algorithms=['RS256'], audience='demo-app', issuer=issuer)['sub'] == subject
    assert stack.document(protocol + 'userinfo', headers={'Authorization': 'Bearer ' + tokens['access_token']})['sub'] == subject

    # Include encoded controls, header/body values, and a response Location sentinel.
    sentinels = {name: 'private-' + secrets.token_hex(16) for name in
                 ('query', 'authorization', 'cookie', 'agent', 'form', 'code', 'token', 'referrer', 'request_id', 'location')}
    stack.sensitive.extend(sentinels.values())
    sensitive_headers = {'Authorization': 'Bearer ' + sentinels['authorization'],
        'Cookie': 'probe=' + sentinels['cookie'], 'User-Agent': sentinels['agent'],
        'Referer': 'https://localhost/?value=' + sentinels['referrer'],
        'X-Request-ID': sentinels['request_id'], 'X-Forwarded-For': '203.0.113.199',
        'X-Forwarded-Proto': 'http', 'X-Forwarded-Host': 'untrusted.invalid'}
    status, headers, _ = stack.request(discovery_path + '?' + urlencode({'probe': sentinels['query'] + '\r\nforged'}), headers=sensitive_headers)
    assert status == 200
    correlation = headers['X-Request-ID']
    assert re.fullmatch('[a-f0-9]{32}', correlation)
    assert stack.request(protocol + 'token', data=dict(grant_type='authorization_code',
        client_id='demo-app', code=sentinels['code'], refresh_token=sentinels['token'],
        password=sentinels['form']), headers=sensitive_headers)[0] == 401
    status, headers, _ = stack.request(protocol + 'auth?' + urlencode(params | {
        'scope': 'unsupported', 'state': sentinels['location']}), headers=sensitive_headers)
    assert status == 302 and sentinels['location'] in headers['Location']
    stack.compose('stop', '--timeout', '20', 'web')
    assert stack.request(discovery_path + '?probe=' + sentinels['query'], headers=sensitive_headers)[0] == 502
    stack.compose('restart', '--no-deps', '--timeout', '20', 'web')
    stack.healthy()
    assert stack.document(discovery_path)['issuer'] == issuer
    assert stack.document(protocol + 'certs')['keys'] == rotated
    assert stack.document(protocol + 'userinfo', headers={'Authorization': 'Bearer ' + fresh['access_token']})['sub'] == subject
    # Browser cookie, database session, refresh state, and both signing keys survive restart.
    status, headers, _ = stack.request(protocol + 'auth?' + urlencode(params | {'state': secrets.token_hex(16)}))
    assert status == 302 and 'code' in parse_qs(urlsplit(headers['Location']).query)
    refreshed = stack.document(protocol + 'token', data=dict(grant_type='refresh_token',
        client_id='demo-app', refresh_token=fresh['refresh_token']))
    stack.sensitive.extend(refreshed[kind] for kind in ('access_token', 'refresh_token', 'id_token'))
    assert refreshed['session_state'] == fresh['session_state']
    assert jwt.get_unverified_header(refreshed['id_token'])['kid'] == new_key['kid']
    stack.compose('run', '--rm', '--no-deps', 'bootstrap')
    assert stack.document(protocol + 'certs')['keys'] == rotated
    assert stack.document(protocol + 'userinfo', headers={'Authorization': 'Bearer ' + refreshed['access_token']})['sub'] == subject
    assert stack.request(protocol + 'logout', data={'id_token_hint': refreshed['id_token']})[0] == 200
    assert stack.request(protocol + 'userinfo', headers={'Authorization': 'Bearer ' + refreshed['access_token']})[0] == 401
    assert stack.request(protocol + 'token', data=dict(grant_type='refresh_token',
        client_id='demo-app', refresh_token=refreshed['refresh_token']))[0] == 400

    logs = stack.compose('logs', '--no-color', '--no-log-prefix')
    stack.assert_redacted(logs)
    records = [json.loads(line) for line in logs.splitlines() if line.startswith('{')]
    access = next(record for record in records if record.get('request_id') == correlation)
    assert access['event'] == 'http_access'
    assert (access['method'], access['path'], access['status']) == ('GET', discovery_path, 200)
    assert access['remote_address'] != '203.0.113.199'
    assert all('?' not in record['path'] for record in records if record.get('event') == 'http_access')
    # Web restart and explicit idempotent bootstrap do not rerun Compose's original jobs.
    for name in ('migrate', 'bootstrap'):
        assert stack.state(name)['State']['StartedAt'] == statuses[name]['State']['StartedAt']
