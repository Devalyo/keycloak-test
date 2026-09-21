"""Catch accidental public ports, mutable images, secret defaults, and startup jobs."""

import json
from pathlib import Path
import re
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.deployment


def artifact(name):
    path = ROOT / name
    assert path.is_file(), f"Missing deployment artifact: {name}"
    return path.read_text()


def compose():
    return yaml.safe_load(artifact('compose.yaml'))


def test_image_installs_wheels_into_a_separate_nonroot_runtime():
    dockerfile = artifact('Dockerfile')
    stages = re.findall(r'^FROM\s+(\S+)\s+AS\s+(\w+)', dockerfile, re.M | re.I)
    assert len(stages) == 2
    assert all(re.fullmatch(r'python@sha256:[0-9a-f]{64}', image) for image, _ in stages)
    assert '3.14.7-slim-bookworm' in dockerfile
    build, runtime = re.split(r'^FROM\s+', dockerfile, flags=re.M)[1:]
    assert 'pip wheel' in build
    assert '--no-index' in runtime and '--no-cache-dir' in runtime
    assert re.search(r'^USER\s+[1-9][0-9]*:[1-9][0-9]*$', runtime, re.M)
    assert 'PYTHONDONTWRITEBYTECODE=1' in dockerfile
    assert 'PYTHONUNBUFFERED=1' in dockerfile
    assert 'org.opencontainers.image.' in runtime
    assert re.search(r'^HEALTHCHECK\b', runtime, re.M)
    commands = re.findall(r'^CMD\s+(.*)$', runtime, re.M)
    assert len(commands) == 1
    assert json.loads(commands[0]) == ['gunicorn', '--config', '/app/gunicorn.conf.py']
    assert 'ENTRYPOINT' not in runtime
    assert re.search(r'^COPY\s+migrations\s+', runtime, re.M)
    assert not re.search(r'^COPY\s+(?:\.|tests|mini_keycloak)\s', runtime, re.M)
    assert not re.search(r'apt(-get)?\s+install|build-essential|gcc', runtime)


def test_build_context_is_an_allowlist_without_operator_secrets_or_tests():
    patterns = artifact('.dockerignore').splitlines()
    assert patterns[0] == '**'
    allowed = {line for line in patterns if line.startswith('!')}
    assert allowed == {
        '!Dockerfile', '!pyproject.toml', '!README.md', '!mini_keycloak/',
        '!mini_keycloak/**', '!migrations/', '!migrations/**', '!gunicorn.conf.py',
    }
    assert '**/__pycache__/**' in patterns
    assert '**/*.pyc' in patterns


def test_only_gateway_publishes_a_loopback_tls_port():
    config = compose()
    services = config['services']
    assert set(services) == {'postgres', 'migrate', 'bootstrap', 'web', 'caddy'}
    for name, service in services.items():
        assert service.get('network_mode') != 'host'
        assert not service.get('privileged', False)
        if name != 'caddy':
            assert not service.get('ports')
        assert 'docker.sock' not in json.dumps(service)
    assert services['caddy']['ports'] == ['127.0.0.1:${MINI_KEYCLOAK_HTTPS_PORT:-8443}:443']
    for network in ('database', 'proxy'):
        assert config['networks'][network]['internal'] is True
    assert set(services['postgres']['networks']) == {'database'}
    assert set(services['web']['networks']) == {'database', 'proxy'}
    assert 'database' not in services['caddy']['networks']


def test_images_and_volumes_are_pinned_and_jobs_gate_the_web():
    config = compose()
    services = config['services']
    for name, image in [('postgres', 'postgres'), ('caddy', 'caddy')]:
        assert re.fullmatch(image + r'@sha256:[0-9a-f]{64}', services[name]['image'])
    assert services['postgres']['image'].endswith(
        'f02121de6f74d30d8a94cd1d9584125e2178d7e6c377d8130112d4e52d867995')
    assert '17.11-alpine3.24' in artifact('compose.yaml')
    assert '2.11.4-alpine' in artifact('compose.yaml')
    assert services['migrate']['depends_on']['postgres']['condition'] == 'service_healthy'
    assert services['bootstrap']['depends_on']['migrate']['condition'] == 'service_completed_successfully'
    assert services['web']['depends_on']['bootstrap']['condition'] == 'service_completed_successfully'
    assert services['caddy']['depends_on']['web']['condition'] == 'service_healthy'
    assert services['migrate']['command'][-2:] == ['db', 'upgrade']
    assert services['bootstrap']['command'][-1] == 'bootstrap-demo'
    for name in ('migrate', 'bootstrap'):
        assert services[name]['restart'] == 'no'
        assert services[name]['healthcheck']['disable'] is True
    assert not services['web'].get('command')
    assert services['postgres']['healthcheck']['test']
    assert 'postgres_data:/var/lib/postgresql/data' in services['postgres']['volumes']
    for mount in ('caddy_data:/data', 'caddy_config:/config'):
        assert mount in services['caddy']['volumes']
    assert set(config['volumes']) == {'postgres_data', 'caddy_data', 'caddy_config'}


def test_app_jobs_and_web_are_restricted_and_proxy_trust_is_exact():
    services = compose()['services']
    for name in ('web', 'migrate', 'bootstrap'):
        service = services[name]
        assert service['read_only'] is True
        assert service['cap_drop'] == ['ALL']
        assert service['security_opt'] == ['no-new-privileges:true']
        assert service['tmpfs']
        assert re.fullmatch(r'[1-9][0-9]?s', service['stop_grace_period'])
        assert not service.get('volumes')
        env = service['environment']
        assert env['MINI_KEYCLOAK_PROFILE'] == 'production'
        assert env['MINI_KEYCLOAK_EXTERNAL_URL'] == 'https://localhost:${MINI_KEYCLOAK_HTTPS_PORT:-8443}'
        assert env['MINI_KEYCLOAK_SESSION_COOKIE_SECURE'] == 'true'
        assert env['MINI_KEYCLOAK_TRUSTED_HOSTS'] == 'localhost'
        assert env['MINI_KEYCLOAK_PROXY_MODE'] == 'xforwarded'
        assert env['MINI_KEYCLOAK_TRUSTED_PROXY_CIDRS'] == '${MINI_KEYCLOAK_PROXY_ADDRESS:-172.30.83.254}/32'
        assert env['MINI_KEYCLOAK_DATABASE_URL'].startswith('postgresql+psycopg://')
        assert env['MINI_KEYCLOAK_DATABASE_URL'].endswith('?connect_timeout=5')
    assert services['caddy']['networks']['proxy']['ipv4_address'] == '${MINI_KEYCLOAK_PROXY_ADDRESS:-172.30.83.254}'


def test_secrets_have_no_defaults_or_values_in_the_example():
    document = artifact('compose.yaml')
    example = artifact('.env.example')
    for name in ('POSTGRES_PASSWORD', 'MINI_KEYCLOAK_SECRET_KEY', 'MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET'):
        assert re.search(r'\$\{' + name + r':\?[^}]+}', document)
        assert not re.search(r'\$\{' + name + r':-', document)
        assert re.search(r'^' + name + r'=$', example, re.M)
    assert 'PRIVATE KEY' not in document + example
    assert '127.0.0.1' in example


def test_gateway_blocks_health_and_discards_request_logging():
    caddyfile = artifact('deploy/Caddyfile')
    assert 'tls internal' in caddyfile
    assert re.search(r'path\s+/health\s+/health/\*', caddyfile)
    assert re.search(r'respond\s+@\w+\s+"[^"]+"\s+404', caddyfile)
    assert 'header_up X-Forwarded-For {remote_host}' in caddyfile
    assert 'header_up X-Forwarded-Proto https' in caddyfile
    assert 'exclude http.log.access http.log.error' in caddyfile
    site = caddyfile.split('https://localhost', 1)[1]
    assert not re.search(r'^\s*log\b', site, re.M)


def test_operator_environment_and_exported_certificates_are_git_ignored():
    for name in ('.env', '.env.backup', 'deploy/root.crt', 'deploy/private.key', 'deploy/private.pem'):
        result = subprocess.run(['git', 'check-ignore', '--no-index', '--quiet', name],
                                cwd=ROOT, capture_output=True, timeout=5)
        assert result.returncode == 0, f'Operator material is not ignored: {name}'
    result = subprocess.run(['git', 'check-ignore', '--no-index', '--quiet', '.env.example'],
                            cwd=ROOT, capture_output=True, timeout=5)
    assert result.returncode == 1
