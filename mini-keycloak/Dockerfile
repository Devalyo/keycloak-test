# Verified official multi-architecture manifest: python:3.14.7-slim-bookworm
FROM python@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY pyproject.toml README.md ./
COPY mini_keycloak ./mini_keycloak
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

# Same verified python:3.14.7-slim-bookworm manifest; no build/source tree copied.
FROM python@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f AS runtime
LABEL org.opencontainers.image.title="Mini Keycloak" \
      org.opencontainers.image.description="Compact identity and OIDC service" \
      org.opencontainers.image.version="0.1.0"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN --mount=type=bind,from=builder,source=/wheels,target=/wheels \
    python -m pip install --no-cache-dir --no-index --find-links=/wheels mini-keycloak
WORKDIR /app
# Alembic and Gunicorn configuration are explicit operator runtime assets.
COPY migrations ./migrations
COPY gunicorn.conf.py ./gunicorn.conf.py
USER 10001:10001
HEALTHCHECK --interval=5s --timeout=4s --start-period=15s --retries=12 \
    CMD ["python", "-c", "import urllib.request; r=urllib.request.Request('http://127.0.0.1:8000/health/ready', headers={'Host':'localhost'}); urllib.request.urlopen(r, timeout=3).close()"]
CMD ["gunicorn", "--config", "/app/gunicorn.conf.py"]
