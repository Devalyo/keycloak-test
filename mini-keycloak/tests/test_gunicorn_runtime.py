from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
import importlib.metadata
import json
import os
from pathlib import Path
import re
import runpy
import socket
import subprocess
import sys
import time

import pytest


PROJECT = Path(__file__).resolve().parents[1]
CONFIG = PROJECT / 'gunicorn.conf.py'
PREFIX = 'MINI_KEYCLOAK_GUNICORN_'


def clean_environment():
    return {name: value for name, value in os.environ.items()
            if not name.startswith('MINI_KEYCLOAK_') and name not in {'GUNICORN_CMD_ARGS', 'PORT', 'WEB_CONCURRENCY'}}


def load_config(monkeypatch, **settings):
    assert CONFIG.is_file(), 'Missing Gunicorn configuration'
    for name in tuple(os.environ):
        if name.startswith(PREFIX):
            monkeypatch.delenv(name)
    for name, value in settings.items():
        monkeypatch.setenv(PREFIX + name, value)
    return runpy.run_path(str(CONFIG))


def test_gunicorn_dependency_and_bounded_default_runtime(monkeypatch):
    requirements = importlib.metadata.requires('mini-keycloak')
    assert any(re.match(r'gunicorn\b', value, re.I) for value in requirements)
    config = load_config(monkeypatch)
    assert config['bind'] == '127.0.0.1:8000'
    assert config['wsgi_app'] == 'mini_keycloak.wsgi:app'
    assert 1 <= config['workers'] <= 16 and 1 <= config['threads'] <= 16
    assert 1 <= config['timeout'] <= 300
    assert 1 <= config['graceful_timeout'] <= 120
    assert 1 <= config['keepalive'] <= 30
    assert config['preload_app'] is False
    assert config['accesslog'] == config['errorlog'] == '-'
    assert config['forwarded_allow_ips'] == ''
    assert '%(U)s' in config['access_log_format']
    for forbidden in ('%(r)', '%(q)', '%(f)', '%(a)', '{authorization}', '{cookie}', '{location}'):
        assert forbidden not in config['access_log_format'].lower()


@pytest.mark.parametrize('name,value', [
    ('WORKERS', '0'), ('WORKERS', '17'), ('WORKERS', '-1'), ('WORKERS', '1.5'),
    ('THREADS', '0'), ('THREADS', '17'), ('THREADS', ' 2'), ('THREADS', 'true'),
    ('TIMEOUT', '0'), ('TIMEOUT', '301'), ('TIMEOUT', ''),
    ('GRACEFUL_TIMEOUT', '0'), ('GRACEFUL_TIMEOUT', '121'),
    ('KEEPALIVE', '0'), ('KEEPALIVE', '31'),
    ('PORT', '0'), ('PORT', '65536'), ('PORT', '8000,9000'),
    ('HOST', 'PRIVATE-host:8000'), ('HOST', 'unix:/PRIVATE-socket'),
    ('HOST', '127.0.0.1\nPRIVATE-forged'), ('HOST', ''),
])
def test_invalid_runtime_values_fail_without_echoing_them(monkeypatch, name, value):
    assert CONFIG.is_file(), 'Missing Gunicorn configuration'
    with pytest.raises(ValueError) as error:
        load_config(monkeypatch, **{name: value})
    assert str(error.value) == 'Invalid ' + PREFIX + name


def test_runtime_accepts_explicit_bounded_values(monkeypatch):
    config = load_config(monkeypatch, HOST='0.0.0.0', PORT='8443', WORKERS='3', THREADS='4',
        TIMEOUT='60', GRACEFUL_TIMEOUT='20', KEEPALIVE='10')
    assert config['bind'] == '0.0.0.0:8443'
    assert (config['workers'], config['threads'], config['timeout'],
            config['graceful_timeout'], config['keepalive']) == (3, 4, 60, 20, 10)
    assert load_config(monkeypatch, HOST='::1')['bind'] == '[::1]:8000'


def http_request(port, method, path, headers=None, body=None):
    connection = HTTPConnection('127.0.0.1', port, timeout=3)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def test_wsgi_import_does_not_create_database_or_dump_settings(tmp_path):
    assert (PROJECT / 'mini_keycloak' / 'wsgi.py').is_file(), 'Missing WSGI entry point'
    database = tmp_path / 'not-created.sqlite'
    env = clean_environment() | {
        'MINI_KEYCLOAK_DATABASE_URL': f'sqlite:///{database}',
        'MINI_KEYCLOAK_SECRET_KEY': 'PRIVATE-application-secret',
    }
    result = subprocess.run([sys.executable, '-c', 'from mini_keycloak.wsgi import app; assert app'],
                            cwd=PROJECT, env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert not database.exists()
    assert 'PRIVATE' not in result.stdout + result.stderr and str(database) not in result.stderr
    records = [json.loads(line) for line in result.stderr.splitlines()]
    assert all(record['level'] != 'CRITICAL' for record in records)


def test_real_gunicorn_health_errors_and_logs_are_correlated_and_secret_safe(tmp_path):
    assert CONFIG.is_file(), 'Missing Gunicorn configuration'
    with socket.socket() as allocator:
        allocator.bind(('127.0.0.1', 0))
        port = allocator.getsockname()[1]
    database = tmp_path / 'isolated.sqlite'
    env = clean_environment() | {
        PREFIX + 'PORT': str(port), PREFIX + 'WORKERS': '2', PREFIX + 'THREADS': '2',
        'MINI_KEYCLOAK_DATABASE_URL': f'sqlite:///{database}',
        'MINI_KEYCLOAK_SECRET_KEY': 'PRIVATE-application-secret',
        'MINI_KEYCLOAK_LOG_LEVEL': 'DEBUG',
    }
    responses = []
    log_file = tmp_path / 'gunicorn.log'
    with log_file.open('w+') as logs:
        process = subprocess.Popen([sys.executable, '-m', 'gunicorn', '--config', str(CONFIG)],
            cwd=PROJECT, env=env, stdout=logs, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    pytest.fail('Gunicorn exited before readiness: ' + log_file.read_text())
                try:
                    if http_request(port, 'GET', '/health/live')[0] == 200:
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                pytest.fail('Gunicorn did not become live within 20 seconds')

            headers = {'X-Request-ID': 'a' * 32, 'Cookie': 'session=PRIVATE-cookie',
                'Authorization': 'Bearer PRIVATE-authorization', 'User-Agent': 'PRIVATE-user-agent',
                'Referer': 'https://PRIVATE-referrer.invalid', 'Content-Type': 'application/x-www-form-urlencoded'}
            paths = [('/health/live?code=PRIVATE-code&secret=PRIVATE-secret&token=PRIVATE-token', 200),
                ('/health/ready?query=PRIVATE-query', 503),
                ('/realms/missing/.well-known/openid-configuration?code=PRIVATE-oidc-code', 500),
                ('/realms/missing/protocol/openid-connect/token', 500),
                ('/missing?query=PRIVATE-crlf%0d%0aPRIVATE-forged', 404),
                ('/health/live/', 404)]
            for path, expected in paths:
                method = 'POST' if path.endswith('/token') else 'GET'
                status, values, _ = http_request(port, method, path, headers,
                    'password=PRIVATE-body&client_secret=PRIVATE-client-secret' if method == 'POST' else None)
                assert status == expected
                responses.append((path.split('?')[0], status, values['X-Request-ID']))
            status, values, _ = http_request(port, 'GET', '/health/live', headers | {'Host': 'PRIVATE-host.invalid'})
            assert status == 400
            responses.append(('/health/live', status, values['X-Request-ID']))
            # A slash-normalizing redirect reflects the query in Location, which must never enter logs.
            status, values, _ = http_request(port, 'GET', '/health//live?code=PRIVATE-location', headers)
            assert status == 308 and 'PRIVATE-location' in values['Location']
            responses.append(('/health//live', status, values['X-Request-ID']))
            with ThreadPoolExecutor(max_workers=4) as pool:
                parallel = list(pool.map(lambda _: http_request(port, 'GET', '/health/live', headers), range(12)))
            responses.extend(('/health/live', status, values['X-Request-ID']) for status, values, _ in parallel)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                pytest.fail('Gunicorn did not terminate cleanly')
    assert process.returncode == 0
    output = log_file.read_text()
    assert 'PRIVATE' not in output and str(database) not in output
    records = [json.loads(line) for line in output.splitlines()]
    access = [record for record in records if record.get('event') == 'http_access']
    assert len({value for _, _, value in responses}) == len(responses)
    for path, status, value in responses:
        assert re.fullmatch('[0-9a-f]{32}', value) and value != 'a' * 32
        matches = [record for record in access if record['request_id'] == value]
        assert len(matches) == 1
        record = matches[0]
        assert set(record) == {'event', 'method', 'path', 'status', 'response_size',
                               'duration_us', 'remote_address', 'request_id'}
        assert record['path'] == path and record['status'] == status
        assert record['method'] in {'GET', 'POST'}
        assert record['response_size'] >= 0 and record['duration_us'] >= 0
        assert record['remote_address'] == '127.0.0.1'
    failures = [record for record in records if record.get('event') in {'oidc', 'token', 'health'}]
    assert failures and all(record['request_id'] in {value for _, _, value in responses} for record in failures)
    assert not [record for record in records if record.get('level') == 'CRITICAL']
