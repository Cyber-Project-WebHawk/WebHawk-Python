import os
import subprocess
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Set test environment BEFORE importing any project modules, so
# service/user_service.py's fail-fast JWT_SECRET check and db/database.py's
# connection pool both pick up test-specific values rather than whatever a
# local .env file (if any) contains. load_dotenv() never overrides
# variables that are already set, so this takes priority.
os.environ["DB_HOST"] = os.getenv("TEST_DB_HOST", "localhost")
os.environ["DB_NAME"] = os.getenv("TEST_DB_NAME", "webhawk_test")
os.environ["DB_USER"] = os.getenv("TEST_DB_USER", "postgres")
os.environ["DB_PASSWORD"] = os.getenv("TEST_DB_PASSWORD", "webhawk1234")
os.environ["DB_PORT"] = os.getenv("TEST_DB_PORT", "5432")
os.environ["JWT_SECRET"] = "pytest-test-secret-do-not-use-in-production"
os.environ["FLASK_DEBUG"] = "false"

sys.path.insert(0, PROJECT_ROOT)

import psycopg2
from psycopg2 import sql as psql


def _recreate_test_database():
    """
    Drops and recreates a dedicated webhawk_test database (never the real
    one), then runs the project's own db/create_tables.py exactly as the
    README documents - so the test suite exercises the real setup path
    instead of a parallel reimplementation of it.
    """
    admin_conn = psycopg2.connect(
        host=os.environ["DB_HOST"],
        dbname="postgres",
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        port=os.environ["DB_PORT"],
    )
    admin_conn.autocommit = True
    cur = admin_conn.cursor()
    db_name = os.environ["DB_NAME"]
    cur.execute(psql.SQL("DROP DATABASE IF EXISTS {}").format(psql.Identifier(db_name)))
    cur.execute(psql.SQL("CREATE DATABASE {}").format(psql.Identifier(db_name)))
    cur.close()
    admin_conn.close()

    subprocess.run(
        [sys.executable, os.path.join(PROJECT_ROOT, "db", "create_tables.py")],
        cwd=PROJECT_ROOT,
        env=os.environ.copy(),
        check=True,
    )


@pytest.fixture(scope="session")
def _test_db():
    _recreate_test_database()
    yield


@pytest.fixture(autouse=True)
def _clean_tables(_test_db):
    """Truncates every table before each test for isolation, regardless of
    execution order."""
    import db.database as dbmod

    conn = dbmod.get_connection()
    cur = conn.cursor()
    cur.execute(
        "TRUNCATE users, user_sessions, backend_registration, "
        "security_logs, rate_limit RESTART IDENTITY CASCADE;"
    )
    conn.commit()
    cur.close()
    dbmod.release_connection(conn)
    yield


@pytest.fixture
def client():
    import app as app_module

    app_module.app.testing = True
    with app_module.app.test_client() as c:
        yield c


@pytest.fixture
def auth_client(client):
    """Registers and logs in a fresh user; returns (client, token)."""
    client.post("/auth/register", json={"username": "tester", "password": "testpass123"})
    resp = client.post("/auth/login", json={"username": "tester", "password": "testpass123"})
    token = resp.get_json()["token"]
    return client, token
