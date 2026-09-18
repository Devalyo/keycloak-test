"""Honor source/scheme forwarding only from configured immediate peers."""

import ipaddress
from urllib.parse import urlsplit

from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers import Response


class TrustedProxy:
    def __init__(self, app, *, mode, cidrs, hops, hosts):
        self.app = app
        self.networks = tuple(ipaddress.ip_network(cidr) for cidr in cidrs) if mode == 'xforwarded' else ()
        self.hosts = frozenset(hosts)
        self.forwarded = ProxyFix(self._without_forwarding, x_for=hops, x_proto=hops,
                                  x_host=0, x_port=0, x_prefix=0)

    def _without_forwarding(self, environ, start_response):
        for key in tuple(environ):
            if key == 'HTTP_FORWARDED' or key.startswith('HTTP_X_FORWARDED_'):
                environ.pop(key, None)
        return self.app(environ, start_response)

    def __call__(self, environ, start_response):
        # Validate exact hosts here as well as Flask's TRUSTED_HOSTS: Werkzeug
        # versions that split hosts at the first ':' cannot distinguish IPv6s.
        host = environ.get('HTTP_HOST', environ.get('SERVER_NAME', ''))
        try:
            parsed = urlsplit('//' + host)
            hostname = parsed.hostname or ''
            canonical = ('[' + ipaddress.IPv6Address(hostname).compressed + ']'
                         if ':' in hostname else hostname.encode('idna').decode('ascii').lower())
            valid_host = (canonical in self.hosts and parsed.username is None and parsed.password is None
                          and not parsed.path and not parsed.query and not parsed.fragment
                          and not any(ord(char) <= 32 or ord(char) == 127 or char in '\\?#%' for char in host)
                          and not host.endswith(':') and (parsed.port is None or 1 <= parsed.port <= 65535))
        except (ValueError, UnicodeError):
            valid_host = False
        if not valid_host:
            return Response('Invalid Host', status=400, content_type='text/plain')(environ, start_response)
        # Flask's host allow-list compares strings; normalize the already
        # validated authority so DNS case and equivalent IPv6 spellings agree.
        environ['HTTP_HOST'] = canonical + (':' + str(parsed.port) if parsed.port is not None else '')
        try:
            peer = ipaddress.ip_address(environ.get('REMOTE_ADDR', ''))
        except ValueError:
            peer = None
        if peer is not None and any(peer in network for network in self.networks):
            return self.forwarded(environ, start_response)
        return self._without_forwarding(environ, start_response)
