from urllib.parse import urlencode, urlsplit, urlunsplit

from flask import redirect, render_template

from mini_keycloak.oidc.errors import OAuthError


def authorization_redirect(redirect_uri: str, parameters: dict[str, str]) -> str:
    """Append protocol fields without rewriting an existing registered query."""
    target = urlsplit(redirect_uri)
    query = target.query + ('&' if target.query else '') + urlencode(parameters)
    return urlunsplit(target._replace(query=query))


def authorization_error(error: OAuthError):
    if error.redirect_uri is None:
        return render_template('error.html'), error.status_code
    parameters = {'error': error.error}
    if error.state is not None:
        parameters['state'] = error.state
    return redirect(authorization_redirect(error.redirect_uri, parameters))
