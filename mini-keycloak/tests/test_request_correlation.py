from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import json
import logging
import re

import pytest
from flask import Response

from mini_keycloak.app import create_app
from mini_keycloak.security import logging as safe_logging


def request_id(response):
    value = response.headers.get('X-Request-ID', '')
    assert re.fullmatch('[0-9a-f]{32}', value)
    return value


@pytest.mark.parametrize('path,host,status', [
    ('/health/live', 'localhost', 200),
    ('/missing', 'localhost', 404),
    ('/health/live', 'untrusted.invalid', 400),
])
def test_server_generates_id_even_before_flask_dispatch(path, host, status):
    client = create_app().test_client()
    supplied = 'a' * 32
    responses = [client.get(path, headers={'Host': host, 'X-Request-ID': supplied}) for _ in range(2)]
    assert all(response.status_code == status for response in responses)
    ids = {request_id(response) for response in responses}
    assert len(ids) == 2 and supplied not in ids


def test_nested_logs_share_response_id_and_context_is_cleared(caplog):
    app = create_app()

    @app.get('/nested')
    def nested():
        safe_logging.log_failure('logout')
        safe_logging.log_failure('audit')
        return Response('ok', headers={'X-Request-ID': 'untrusted-response-id'})

    caplog.clear()
    response = app.test_client().get('/nested')
    expected = request_id(response)
    assert len(caplog.records) == 2
    assert {getattr(record, 'request_id', None) for record in caplog.records} == {expected}
    assert safe_logging.current_request_id() is None
    caplog.clear()
    with app.app_context():
        safe_logging.log_failure('audit')
    assert getattr(caplog.records[0], 'request_id', None) is None


def test_concurrent_requests_do_not_share_correlation(caplog):
    app = create_app()
    barrier = Barrier(4)

    @app.get('/parallel')
    def parallel():
        barrier.wait(timeout=5)
        safe_logging.log_failure('oidc')
        barrier.wait(timeout=5)
        safe_logging.log_failure('audit')
        return 'ok'

    caplog.clear()
    def call(_):
        response = app.test_client().get('/parallel')
        assert safe_logging.current_request_id() is None
        return request_id(response)

    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(call, range(4)))
    assert len(set(ids)) == 4
    assert sorted(record.request_id for record in caplog.records) == sorted(ids * 2)


@pytest.mark.parametrize('failure', ['call', 'iterate', 'close'])
def test_wsgi_context_survives_streaming_and_clears_after_exceptions(failure):
    assert hasattr(safe_logging, 'RequestCorrelation'), 'Missing request correlation middleware'
    seen = []
    headers = []

    class Body:
        def __iter__(self):
            seen.append(safe_logging.current_request_id())
            yield b'first'
            if failure == 'iterate':
                raise RuntimeError('stream failure')

        def close(self):
            seen.append(safe_logging.current_request_id())
            if failure == 'close':
                raise RuntimeError('close failure')

    def wsgi(environ, start_response):
        seen.append(safe_logging.current_request_id())
        if failure == 'call':
            raise RuntimeError('call failure')
        start_response('200 OK', [])
        return Body()

    middleware = safe_logging.RequestCorrelation(wsgi)
    if failure == 'call':
        with pytest.raises(RuntimeError, match='call failure'):
            middleware({}, lambda status, values, exc_info=None: headers.extend(values))
    else:
        result = middleware({}, lambda status, values, exc_info=None: headers.extend(values))
        assert safe_logging.current_request_id() is None
        iterator = iter(result)
        assert next(iterator) == b'first'
        assert safe_logging.current_request_id() is None
        if failure == 'iterate':
            with pytest.raises(RuntimeError, match='stream failure'):
                next(iterator)
        if failure == 'close':
            with pytest.raises(RuntimeError, match='close failure'):
                result.close()
        else:
            result.close()
        assert dict(headers)['X-Request-ID'] == seen[0]
    assert safe_logging.current_request_id() is None
    assert len(set(seen)) == 1 and re.fullmatch('[0-9a-f]{32}', seen[0])


def test_application_json_uses_only_fixed_fields_and_escapes_controls():
    assert hasattr(safe_logging, 'JsonFormatter'), 'Missing structured application formatter'
    formatter = safe_logging.JsonFormatter()
    try:
        raise RuntimeError('PRIVATE-exception\r\nforged')
    except RuntimeError:
        import sys
        record = logging.LogRecord('mini_keycloak.test\r\nlogger', logging.ERROR,
            __file__, 1, 'PRIVATE-message %s', ('PRIVATE-argument',), sys.exc_info())
    record.stack_info = 'PRIVATE-stack'
    record.secret = 'PRIVATE-extra'
    record.request_id = 'PRIVATE-inbound-id'
    line = formatter.format(record)
    assert len(line.splitlines()) == 1
    data = json.loads(line)
    assert set(data) == {'timestamp', 'level', 'logger', 'event', 'message'}
    assert data['level'] == 'ERROR'
    assert re.fullmatch(r'\d{4}-\d\d-\d\dT.*Z', data['timestamp'])
    assert 'PRIVATE' not in line
    assert '\\r\\n' in line


def test_factory_logging_is_idempotent_and_does_not_disclose_configuration(caplog):
    for secret in ('PRIVATE-first', 'PRIVATE-second'):
        create_app({'SECRET_KEY': secret})
    records = [record for record in caplog.records if record.levelno == logging.CRITICAL]
    assert not records
    assert 'PRIVATE' not in caplog.text
    handlers = [handler for handler in logging.getLogger('mini_keycloak').handlers
                if isinstance(handler.formatter, safe_logging.JsonFormatter)]
    assert len(handlers) == 1


def test_health_failure_uses_the_response_correlation(tmp_path, caplog):
    app = create_app({'SQLALCHEMY_DATABASE_URI': f'sqlite:///{tmp_path}/empty.sqlite'})
    caplog.clear()
    response = app.test_client().get('/health/ready')
    assert response.status_code == 503
    assert {getattr(record, 'request_id', None) for record in caplog.records} == {request_id(response)}
