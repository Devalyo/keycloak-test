"""Check usable operator examples and coverage of the shipped configuration."""

from dataclasses import fields
from pathlib import Path
import re
import shlex
import stat
import subprocess

import pytest
import yaml

from mini_keycloak.config import Settings


PROJECT = Path(__file__).parents[1]
DOCUMENTS = (
    PROJECT.parent / "README.md",
    PROJECT / "README.md",
    PROJECT / "docs/deployment.md",
    PROJECT / "docs/operations.md",
)


def read_document(path):
    assert path.is_file(), f"Missing operator guide: {path.name}"
    return path.read_text()


def snippet(path, name):
    document = read_document(path)
    match = re.search(
        rf"<!-- contract: {re.escape(name)} -->\s*```bash\n(.*?)\n```",
        document,
        re.DOTALL,
    )
    assert match, f"Missing runnable example: {name}"
    return match.group(1)


def test_configuration_reference_covers_every_application_runtime_and_compose_setting():
    document = read_document(PROJECT / "docs/deployment.md")
    documented = set(re.findall(r"^\| `([A-Z][A-Z0-9_]+)` \|", document, re.MULTILINE))
    required = {"MINI_KEYCLOAK_" + field.name.upper() for field in fields(Settings)}
    required.update("MINI_KEYCLOAK_GUNICORN_" + name for name in (
        "HOST", "PORT", "WORKERS", "THREADS", "TIMEOUT", "GRACEFUL_TIMEOUT", "KEEPALIVE",
    ))
    required.update(re.findall(r"\$\{([A-Z][A-Z0-9_]+)", (PROJECT / "compose.yaml").read_text()))
    assert not required - documented, f"Undocumented settings: {sorted(required - documented)}"


def test_secret_example_creates_independent_private_values_without_printing_or_overwriting(tmp_path):
    command = snippet(PROJECT / "docs/deployment.md", "compose-secrets")
    (tmp_path / ".env.example").write_bytes((PROJECT / ".env.example").read_bytes())
    first = subprocess.run(["bash", "-c", command], cwd=tmp_path, text=True, capture_output=True, timeout=10)
    assert first.returncode == 0, first.stderr
    assert first.stdout == first.stderr == ""
    env_file = tmp_path / ".env"
    original = env_file.read_bytes()
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    values = dict(line.split("=", 1) for line in original.decode().splitlines() if line and not line.startswith("#"))
    secret_names = ("POSTGRES_PASSWORD", "MINI_KEYCLOAK_SECRET_KEY", "MINI_KEYCLOAK_OIDC_KEY_ENCRYPTION_SECRET")
    secrets = [values[name] for name in secret_names]
    assert len(set(secrets)) == 3
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in secrets)
    second = subprocess.run(["bash", "-c", command], cwd=tmp_path, text=True, capture_output=True, timeout=10)
    assert second.returncode != 0
    assert env_file.read_bytes() == original
    assert all(value not in second.stdout + second.stderr for value in secrets)


def test_compose_examples_use_real_services_and_explicit_job_commands():
    document = read_document(PROJECT / "docs/deployment.md")
    compose = yaml.safe_load((PROJECT / "compose.yaml").read_text())
    jobs = snippet(PROJECT / "docs/deployment.md", "compose-jobs")
    for service in ("migrate", "bootstrap"):
        expected = ["docker", "compose", "run", "--rm", "--no-deps", service]
        assert expected in [shlex.split(line) for line in jobs.splitlines() if line.strip()]
        assert compose["services"][service]["command"][:3] == ["flask", "--app", "mini_keycloak.app:create_app"]
    for command in (
        "docker compose config --quiet", "docker compose build", "docker compose up -d",
        "docker compose ps -a", "docker compose restart --no-deps web",
        "docker compose down", "docker compose down --volumes",
    ):
        assert re.search(rf"^{re.escape(command)}$", document, re.MULTILINE), command


def test_tls_example_exports_only_the_public_ca_and_verifies_the_loopback_origin():
    command = snippet(PROJECT / "docs/deployment.md", "compose-trust")
    assert "caddy:/data/caddy/pki/authorities/local/root.crt" in command
    assert "--cacert deploy/local-ca.crt" in command
    assert "https://localhost:8443/realms/demo/.well-known/openid-configuration" in command
    tokens = shlex.split(command)
    assert not {"-k", "--insecure"} & set(tokens)
    assert not re.search(r"(?:root|intermediate)\.key", command)


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda path: path.name)
def test_documented_shell_examples_parse_without_execution(path):
    for index, command in enumerate(re.findall(r"```bash\n(.*?)\n```", read_document(path), re.DOTALL)):
        result = subprocess.run(["bash", "-n"], input=command, text=True, capture_output=True, timeout=5)
        assert result.returncode == 0, f"{path.name} example {index}: {result.stderr}"


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda path: path.name)
def test_local_documentation_links_resolve(path):
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", read_document(path)):
        if "://" in target or target.startswith("#"):
            continue
        assert (path.parent / target.split("#", 1)[0]).exists(), f"Broken link in {path.name}: {target}"


def test_recovery_examples_use_consistent_native_backup_and_transactional_restore():
    command = snippet(PROJECT / "docs/operations.md", "postgres-backup")
    assert "docker compose exec -T postgres pg_dump" in command
    assert "--format=custom" in command
    assert "umask 077" in command
    restore = snippet(PROJECT / "docs/operations.md", "postgres-restore")
    assert "docker compose exec -T postgres pg_restore" in restore
    assert "--single-transaction" in restore
    assert "--exit-on-error" in restore
    assert "--no-owner" in restore
    assert "--clean" not in restore
    assert not re.search(r"(?:PASSWORD|SECRET_KEY)=\S+", command + restore)
