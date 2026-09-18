from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
import re
from uuid import uuid4

from flask import current_app
from flask.logging import wsgi_errors_stream
from gunicorn.glogging import Logger


_FAILURE_MESSAGES = {
    'oidc': 'OIDC request failed unexpectedly',
    'token': 'Token request failed unexpectedly',
    'logout': 'Logout request failed unexpectedly',
    'browser': 'Browser request failed unexpectedly',
    'audit': 'Security event persistence failed',
    'health': 'Health readiness check failed',
}

_EVENT_MESSAGES = _FAILURE_MESSAGES | {
    'refresh_audit': 'Refresh reuse event persistence failed',
    'application': 'Application event',
    'gunicorn': 'Gunicorn runtime event',
}
_MESSAGE_EVENTS = {message: event for event, message in _EVENT_MESSAGES.items()}
_REQUEST_ID = ContextVar('mini_keycloak_request_id', default=None)


def current_request_id():
    return _REQUEST_ID.get()


class _CorrelatedBody:
    """Re-enter context for iteration/close without leaking it between yields."""

    def __init__(self, body, request_id):
        self.body = body
        self.iterator = None
        self.request_id = request_id

    def __iter__(self):
        return self

    def __next__(self):
        token = _REQUEST_ID.set(self.request_id)
        try:
            if self.iterator is None:
                self.iterator = iter(self.body)
            return next(self.iterator)
        finally:
            _REQUEST_ID.reset(token)

    def close(self):
        token = _REQUEST_ID.set(self.request_id)
        try:
            close = getattr(self.body, 'close', None)
            if close is not None:
                close()
        finally:
            _REQUEST_ID.reset(token)


class RequestCorrelation:
    """Outer WSGI boundary: generate IDs before proxy/Host/request parsing."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        request_id = uuid4().hex
        token = _REQUEST_ID.set(request_id)

        def correlated_response(status, headers, exc_info=None):
            headers = [(key, value) for key, value in headers if key.lower() != 'x-request-id']
            headers.append(('X-Request-ID', request_id))
            return start_response(status, headers, exc_info)

        try:
            return _CorrelatedBody(self.app(environ, correlated_response), request_id)
        finally:
            _REQUEST_ID.reset(token)


def _event(record):
    fallback = 'gunicorn' if record.name.startswith('gunicorn.') else 'application'
    return _MESSAGE_EVENTS.get(record.msg, fallback) if isinstance(record.msg, str) else fallback


class ApplicationLogFilter(logging.Filter):
    def filter(self, record):
        # Sanitize the record itself before propagation to other logging sinks.
        record.event = _event(record)
        record.msg = _EVENT_MESSAGES[record.event]
        record.args = ()
        record.exc_info = record.exc_text = record.stack_info = None
        record.request_id = current_request_id()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record):
        event = _event(record)
        data = {
            'timestamp': datetime.fromtimestamp(record.created, timezone.utc).isoformat(
                timespec='milliseconds').replace('+00:00', 'Z'),
            'level': record.levelname,
            'logger': record.name,
            'event': event,
            'message': _EVENT_MESSAGES[event],
        }
        request_id = getattr(record, 'request_id', None)
        if isinstance(request_id, str) and re.fullmatch('[0-9a-f]{32}', request_id):
            data['request_id'] = request_id
        return json.dumps(data, ensure_ascii=True, separators=(',', ':'))


class AccessJsonFormatter(logging.Formatter):
    def format(self, record):
        atoms = record.args
        return json.dumps({
            'event': 'http_access',
            'method': atoms['m'],
            'path': atoms['U'],
            'status': int(atoms['s']),
            'response_size': int(atoms['B'] or 0),
            'duration_us': atoms['D'],
            'remote_address': atoms['h'],
            'request_id': atoms['{x-request-id}o'],
        }, ensure_ascii=True, separators=(',', ':'))


class SecretSafeGunicornLogger(Logger):
    # JSON performs all escaping; Gunicorn's text-log quoting would double it.
    atoms_wrapper_class = dict

    def setup(self, cfg):
        super().setup(cfg)
        self.error_log.addFilter(_APPLICATION_FILTER)
        for handler in self.error_log.handlers:
            handler.setFormatter(JsonFormatter())
        for handler in self.access_log.handlers:
            handler.setFormatter(AccessJsonFormatter())

    def atoms(self, resp, req, environ, request_time):
        # Never collect query, request headers, body, environment, or Location.
        headers = resp.headers.items() if hasattr(resp.headers, 'items') else resp.headers
        request_id = next((value for key, value in headers if key.lower() == 'x-request-id'), None)
        if not isinstance(request_id, str) or not re.fullmatch('[0-9a-f]{32}', request_id):
            request_id = None
        status = resp.status.split(None, 1)[0] if isinstance(resp.status, str) else resp.status
        return {
            'm': environ.get('REQUEST_METHOD'),
            'U': environ.get('PATH_INFO'),
            's': status,
            'B': getattr(resp, 'sent', 0),
            'D': int(request_time.total_seconds() * 1000000),
            'h': environ.get('REMOTE_ADDR'),
            '{x-request-id}o': request_id,
        }


_APPLICATION_FILTER = ApplicationLogFilter()
_APPLICATION_HANDLER = logging.StreamHandler(wsgi_errors_stream)
_APPLICATION_HANDLER.addFilter(_APPLICATION_FILTER)
_APPLICATION_HANDLER.setFormatter(JsonFormatter())


def configure_application_logging(app):
    logger = logging.getLogger('mini_keycloak')
    logger.setLevel(app.config['LOG_LEVEL'])
    logger.addHandler(_APPLICATION_HANDLER)
    # Flask's logger also filters before any externally configured root handler.
    app.logger.addFilter(_APPLICATION_FILTER)


def _without_query(value):
    if not isinstance(value, str) or '?' not in value:
        return value
    # Drop the entire remainder, including ambiguous malformed request lines.
    # Parameter-name lists cannot cover future secrets or encoded/empty names.
    prefix = value.partition('?')[0]
    return re.sub(r'\x1b\[[0-9;]*m', '', prefix) + '?[REDACTED]'


class QueryRedactionFilter(logging.Filter):
    """Sanitize Werkzeug records before any handler or propagated sink sees them."""

    def filter(self, record):
        if record.levelno >= logging.ERROR:
            # HTTP parsing errors can quote an isolated query fragment as a
            # bad version/method, with no '?' left to recognize. Server errors
            # can also contain request-bearing exception text. Access records
            # separately retain the safe method/path/status when available.
            record.msg = 'HTTP server request failed'
            record.args = ()
            record.exc_info = record.exc_text = record.stack_info = None
            return True
        if isinstance(record.args, dict):
            record.args = {key: _without_query(value) for key, value in record.args.items()}
        else:
            record.args = tuple(_without_query(value) for value in record.args)
        if '?' in str(record.msg):
            # A preformatted request target may be in the message itself. Render
            # first so removing its suffix cannot leave unmatched placeholders.
            record.msg = _without_query(record.getMessage())
            record.args = ()
        return True


_ACCESS_QUERY_FILTER = QueryRedactionFilter()


def configure_access_logging():
    """Safe for repeated factories; the same filter object is installed once."""
    logging.getLogger('werkzeug').addFilter(_ACCESS_QUERY_FILTER)


def log_failure(operation):
    """Log a fixed message using the surrounding request's correlation context."""
    message = _FAILURE_MESSAGES.get(operation, _FAILURE_MESSAGES['oidc'])
    current_app.logger.error(message)
