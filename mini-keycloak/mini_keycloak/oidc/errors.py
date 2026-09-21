class OAuthError(Exception):
    """Safe protocol error; redirect destinations must already be validated."""

    error = 'invalid_request'

    def __init__(self, *, redirect_uri=None, state=None, status_code=400):
        super().__init__(self.error)
        self.redirect_uri = redirect_uri
        self.state = state
        self.status_code = status_code


class InvalidRequest(OAuthError):
    error = 'invalid_request'


class InvalidScope(OAuthError):
    error = 'invalid_scope'


class UnauthorizedClient(OAuthError):
    error = 'unauthorized_client'


class AccessDenied(OAuthError):
    error = 'access_denied'


class InvalidGrant(OAuthError):
    error = 'invalid_grant'


class RefreshReuse(InvalidGrant):
    """Persist the defensive revocation even though the grant was rejected."""


class InvalidClient(OAuthError):
    error = 'invalid_client'

    def __init__(self):
        super().__init__(status_code=401)


class UnsupportedGrantType(OAuthError):
    error = 'unsupported_grant_type'


class InvalidToken(OAuthError):
    error = 'invalid_token'

    def __init__(self):
        super().__init__(status_code=401)


class TemporarilyUnavailable(OAuthError):
    error = 'temporarily_unavailable'

    def __init__(self):
        super().__init__(status_code=503)
