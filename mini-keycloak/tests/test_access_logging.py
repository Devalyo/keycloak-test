from http.client import HTTPConnection
from http.cookies import SimpleCookie
from datetime import timedelta
import json
import logging
import socket
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from werkzeug.serving import WSGIRequestHandler

from mini_keycloak.app import create_app
from mini_keycloak.security.logging import AccessJsonFormatter, SecretSafeGunicornLogger
from tests.helpers import form_action
from tests.test_authorization_code import AUTH, CHALLENGE, PARAMS, VERIFIER
from tests.test_client_authentication import TOKEN
from tests.test_logout import LOGOUT
from tests.test_userinfo import USERINFO


def messages(caplog):
    return '\n'.join(record.getMessage() for record in caplog.records if record.name == 'werkzeug')


def test_gunicorn_json_escapes_path_controls_without_collecting_request_secrets():
    logger = object.__new__(SecretSafeGunicornLogger)
    response = SimpleNamespace(status='302 Found', sent=12,
        headers=[('X-Request-ID', 'b' * 32), ('Location', 'PRIVATE-location')])
    environ = {'REQUEST_METHOD': 'GET', 'PATH_INFO': '/path"\r\nnext',
        'QUERY_STRING': 'code=PRIVATE-code', 'RAW_URI': '/path?PRIVATE-raw',
        'HTTP_COOKIE': 'PRIVATE-cookie', 'REMOTE_ADDR': '127.0.0.1'}
    atoms = logger.atoms(response, SimpleNamespace(headers={'Authorization': 'PRIVATE-header'}),
                         environ, timedelta(microseconds=23))
    assert 'PRIVATE' not in repr(atoms)
    record = logging.LogRecord('gunicorn.access', logging.INFO, __file__, 1, '', (atoms,), None)
    line = AccessJsonFormatter().format(record)
    assert len(line.splitlines()) == 1 and 'PRIVATE' not in line
    data = json.loads(line)
    assert data['path'] == '/path"\r\nnext'
    assert (data['status'], data['response_size'], data['duration_us']) == (302, 12, 23)


@pytest.mark.parametrize('query', [
    'id_token_hint=sentinel-token',
    'state=sentinel-state&nonce=sentinel-nonce&code_challenge=sentinel-challenge',
    'tab_id=sentinel-tab&future_parameter=sentinel-future',
    'future=sentinel-first&future=sentinel-second&encoded=sentinel%2Fencoded',
    'sentinel-bare&=sentinel-empty-name&arbitrary=sentinel-space with spaces',
])
def test_real_werkzeug_request_line_arguments_omit_all_query_values(app, caplog, query):
    caplog.set_level(logging.INFO, logger='werkzeug')
    handler = object.__new__(WSGIRequestHandler)
    handler.client_address = ('127.0.0.1', 12345)
    handler.command = 'GET'
    handler.path = '/ordinary?' + query
    handler.request_version = 'HTTP/1.1'
    handler.log_request(200, 12)
    output = messages(caplog)
    assert 'sentinel' not in output
    assert 'GET /ordinary' in output and '200 12' in output
    # Filters must sanitize the record itself before any structured sink sees it.
    assert 'sentinel' not in repr([(record.msg, record.args) for record in caplog.records])


def test_werkzeug_malformed_request_fallback_and_error_omit_query_values(app, caplog):
    caplog.set_level(logging.INFO, logger='werkzeug')
    handler = object.__new__(WSGIRequestHandler)
    handler.client_address = ('127.0.0.1', 12345)
    handler.requestline = 'GET /malformed?future=sentinel-first value=sentinel-last broken HTTP'
    handler.log_request(400)
    handler.log_error('code %d, message %s', 400, 'Bad request syntax (%r)' % handler.requestline)
    output = messages(caplog)
    assert 'sentinel' not in output
    assert 'GET /malformed' in output and '400' in output


def test_factory_access_log_setup_is_idempotent_and_handles_other_url_shapes(caplog):
    caplog.set_level(logging.INFO, logger='werkzeug')
    create_app({'SECRET_KEY': 'first-application'})
    logger = logging.getLogger('werkzeug')
    first_filters = tuple(logger.filters)
    create_app({'SECRET_KEY': 'second-application'})
    assert tuple(logger.filters) == first_filters
    logger.info('url=%(url)s status=%(status)s', {
        'url': 'https://issuer.test/path?future=sentinel-mapping', 'status': 400})
    logger.info('GET /literal?future=sentinel-literal HTTP/1.1')
    logger.info('GET /without-query HTTP/1.1 status=200')
    output = messages(caplog)
    assert 'sentinel' not in output
    assert 'https://issuer.test/path' in output and 'status=400' in output
    assert 'GET /without-query HTTP/1.1 status=200' in output


def request_live(server, method, path, *, data=None, cookie=None):
    connection = HTTPConnection(urlsplit(server.url).netloc, timeout=5)
    headers = {}
    if data is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    if cookie is not None:
        headers['Cookie'] = cookie
    try:
        connection.request(method, path, body=urlencode(data) if data is not None else None, headers=headers)
        response = connection.getresponse()
        body = response.read().decode()
        return response.status, dict(response.getheaders()), body
    finally:
        connection.close()


def test_live_login_and_successful_get_logout_do_not_log_query_values(live_server, caplog):
    caplog.set_level(logging.INFO, logger='werkzeug')
    params = PARAMS | {'state': 'sentinel-state', 'nonce': 'sentinel-nonce'}
    status, headers, body = request_live(live_server, 'GET', AUTH + '?' + urlencode(params))
    assert status == 200
    cookies = SimpleCookie(headers['Set-Cookie'])
    cookie = '; '.join(f'{name}={value.value}' for name, value in cookies.items())
    action = form_action(body, 'authenticate')
    tab_id = parse_qs(urlsplit(action).query)['tab_id'][0]
    status, headers, _ = request_live(live_server, 'POST', action, cookie=cookie,
        data={'username': 'demo-user', 'password': 'DemoPassw0rd!'})
    assert status == 302
    code = parse_qs(urlsplit(headers['Location']).query)['code'][0]
    status, _, body = request_live(live_server, 'POST', TOKEN, data={
        'grant_type': 'authorization_code', 'client_id': 'demo-app', 'code': code,
        'redirect_uri': PARAMS['redirect_uri'], 'code_verifier': VERIFIER})
    assert status == 200
    tokens = json.loads(body)
    status, _, _ = request_live(live_server, 'GET', LOGOUT + '?' + urlencode({
        'id_token_hint': tokens['id_token'], 'state': 'sentinel-logout-state'}))
    assert status == 200
    output = messages(caplog)
    values = [tokens['id_token'], tokens['access_token'], tokens['refresh_token'], code, tab_id,
              CHALLENGE, 'sentinel-state', 'sentinel-nonce', 'sentinel-logout-state', 'DemoPassw0rd!']
    assert not any(value in output for value in values)
    for method, path, status in [('GET', AUTH, 200), ('POST', '/realms/demo/login-actions/authenticate', 302),
                                 ('POST', TOKEN, 200), ('GET', LOGOUT, 200)]:
        assert any(f'{method} {path}' in line and f' {status} ' in line for line in output.splitlines())


@pytest.mark.parametrize('path, query, expected', [
    (USERINFO, 'access_token=sentinel-access', 400),
    ('/unknown', 'future=sentinel-first&future=sentinel-second', 404),
    ('/unknown', 'future=sentinel%2Fencoded&blank=&=sentinel-no-name', 404),
    ('/unknown', 'future=sentinel%20space&other=sentinel%22quote%26value', 404),
    ('/unknown', 'future=sentinel%3Fquestion&other=sentinel%252Fdouble', 404),
])
def test_live_rejected_and_unknown_urls_never_log_query_values(live_server, caplog, path, query, expected):
    caplog.set_level(logging.INFO, logger='werkzeug')
    status, _, _ = request_live(live_server, 'GET', path + '?' + query)
    assert status == expected
    output = messages(caplog)
    assert 'sentinel' not in output
    assert f'GET {path}' in output and f' {status} ' in output


def test_live_malformed_request_parser_does_not_log_query_fragments(live_server, caplog):
    caplog.set_level(logging.INFO, logger='werkzeug')
    destination = urlsplit(live_server.url)
    with socket.create_connection((destination.hostname, destination.port), timeout=5) as connection:
        connection.sendall(b'GET /malformed?future=sentinel-first sentinel-last\r\nHost: localhost\r\n\r\n')
        chunks = []
        while chunk := connection.recv(8192):
            chunks.append(chunk)
    assert b'400' in b''.join(chunks)
    output = messages(caplog)
    assert 'sentinel' not in output
    assert 'GET /malformed' in output and '400' in output
