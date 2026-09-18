"""Run opt-in tests against one disposable, loopback-only PostgreSQL 17.

From the repository root: .venv/bin/python mini-keycloak/tests/postgres/run.py
Extra arguments are pytest arguments. The image must already exist locally.
"""

import os
from pathlib import Path
import secrets
import subprocess
import sys
import time


IMAGE = "sha256:f02121de6f74d30d8a94cd1d9584125e2178d7e6c377d8130112d4e52d867995"


def main():
    container = "mini-keycloak-pg-test-" + secrets.token_hex(16)
    password = secrets.token_urlsafe(48)
    environment = {**os.environ, "POSTGRES_PASSWORD": password,
                   "POSTGRES_USER": "mini_test", "POSTGRES_DB": "mini_test"}
    root = Path(__file__).resolve().parents[3]

    def docker(*args, check=True):
        result = subprocess.run(["docker", *args], env=environment,
                                capture_output=True, text=True, timeout=30)
        if check and result.returncode:
            raise RuntimeError("PostgreSQL test container command failed")
        return result

    try:
        docker("run", "--detach", "--rm", "--pull=never", "--name", container,
               "--publish", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql/data",
               "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_USER", "--env", "POSTGRES_DB", IMAGE)
        deadline = time.monotonic() + 45
        while docker("exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "mini_test", "-d", "mini_test", check=False).returncode:
            if time.monotonic() >= deadline:
                raise RuntimeError("PostgreSQL readiness deadline exceeded")
            time.sleep(0.2)
        port = int(docker("port", container, "5432/tcp").stdout.strip().rsplit(":", 1)[1])
        url = f"postgresql+psycopg://mini_test:{password}@127.0.0.1:{port}/mini_test"
        environment["MINI_KEYCLOAK_TEST_POSTGRES_URL"] = url
        version = docker("exec", container, "psql", "-U", "mini_test", "-d", "mini_test",
                         "-Atc", "SHOW server_version").stdout.strip()
        print(f"PostgreSQL {version}; image {IMAGE}", flush=True)
        arguments = sys.argv[1:] or ["mini-keycloak/tests/postgres", "-m", "postgres", "-v"]
        result = subprocess.run([sys.executable, "-m", "pytest", *arguments], cwd=root,
                                env=environment, capture_output=True, text=True, timeout=300)
        # Even a setup failure must not put generated database credentials in
        # terminal output. No raw subprocess exception/command is displayed.
        for output in (result.stdout, result.stderr):
            print(output.replace(url, "[test database URL]").replace(password, "[redacted]"), end="")
        remaining = docker("exec", container, "psql", "-U", "mini_test", "-d", "mini_test", "-Atc",
                           "SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'mk_test_%'").stdout.strip()
        if remaining != "0":
            raise RuntimeError("Temporary PostgreSQL test schemas remain after pytest teardown")
        print("Temporary schema cleanup verified: zero remaining.", flush=True)
        return result.returncode
    finally:
        # The exact generated name owns a tmpfs; no shared volume is touched.
        docker("rm", "--force", container, check=False)
        if docker("container", "inspect", container, check=False).returncode == 0:
            raise RuntimeError("Disposable PostgreSQL test container cleanup failed")


if __name__ == "__main__":
    raise SystemExit(main())
