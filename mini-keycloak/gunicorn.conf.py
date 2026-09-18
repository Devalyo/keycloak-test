"""Bounded runtime settings; no schema changes or configuration dumps."""

import ipaddress
import os
import re


def _integer(name, default, maximum):
    variable = 'MINI_KEYCLOAK_GUNICORN_' + name
    value = os.environ.get(variable, str(default))
    if not re.fullmatch('[0-9]{1,5}', value) or not 1 <= int(value) <= maximum:
        raise ValueError('Invalid ' + variable)
    return int(value)


def _bind():
    variable = 'MINI_KEYCLOAK_GUNICORN_HOST'
    try:
        host = ipaddress.ip_address(os.environ.get(variable, '127.0.0.1'))
    except ValueError:
        raise ValueError('Invalid ' + variable) from None
    # Scope identifiers have platform-dependent binding semantics.
    if '%' in str(host):
        raise ValueError('Invalid ' + variable)
    address = '[' + str(host) + ']' if host.version == 6 else str(host)
    return address + ':' + str(_integer('PORT', 8000, 65535))


wsgi_app = 'mini_keycloak.wsgi:app'
bind = _bind()
workers = _integer('WORKERS', 2, 16)
threads = _integer('THREADS', 2, 16)
worker_class = 'gthread'
timeout = _integer('TIMEOUT', 30, 300)
graceful_timeout = _integer('GRACEFUL_TIMEOUT', 30, 120)
keepalive = _integer('KEEPALIVE', 5, 30)
preload_app = False
accesslog = '-'
errorlog = '-'
loglevel = 'info'
logger_class = 'mini_keycloak.security.logging.SecretSafeGunicornLogger'
access_log_format = '%(m)s %(U)s %(s)s %(B)s %(D)s %(h)s %({x-request-id}o)s'
# The application's direct-peer middleware owns all forwarding decisions.
forwarded_allow_ips = ''
secure_scheme_headers = {}
forwarder_headers = ''
