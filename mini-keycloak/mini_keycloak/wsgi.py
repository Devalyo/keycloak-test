"""Gunicorn entry point. Schema and realm setup remain explicit operator jobs."""

from mini_keycloak.app import create_app


app = create_app()
