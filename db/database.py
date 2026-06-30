import os
import time
import psycopg2
from psycopg2 import pool as psycopg2_pool
from dotenv import load_dotenv

load_dotenv()

# How many times to retry the *initial* pool creation before giving up.
# This protects against the classic Docker Compose race where the app
# container starts before Postgres is actually ready to accept connections,
# even when `depends_on` ensures start *order*. The retry only happens once,
# the first time a connection is needed - after the pool exists,
# get_connection()/release_connection() are fast borrow/return calls with no
# per-call retry.
MAX_CONNECT_RETRIES = int(os.getenv("DB_CONNECT_MAX_RETRIES", "10"))
RETRY_DELAY_SECONDS = float(os.getenv("DB_CONNECT_RETRY_DELAY", "2"))
POOL_MIN_CONN = int(os.getenv("DB_POOL_MIN_CONN", "1"))
POOL_MAX_CONN = int(os.getenv("DB_POOL_MAX_CONN", "20"))

_pool = None


def _build_pool():
    last_error = None
    for attempt in range(1, MAX_CONNECT_RETRIES + 1):
        try:
            return psycopg2_pool.ThreadedConnectionPool(
                POOL_MIN_CONN,
                POOL_MAX_CONN,
                host=os.getenv("DB_HOST", "localhost"),
                database=os.getenv("DB_NAME", "webhawk"),
                user=os.getenv("DB_USER", "postgres"),
                password=os.getenv("DB_PASSWORD", ""),
                port=int(os.getenv("DB_PORT", 5432)),
            )
        except psycopg2.OperationalError as e:
            last_error = e
            if attempt == MAX_CONNECT_RETRIES:
                break
            time.sleep(RETRY_DELAY_SECONDS)
    raise last_error


def get_connection():
    """
    Borrows a connection from a pool instead of opening a brand-new TCP
    connection to Postgres on every single Repository call (the previous
    behavior - acceptable at student-project scale, but not how this would
    be done at any real production scale). Always pair this with
    release_connection(conn), ideally in a try/finally, to return the
    connection to the pool rather than leaking it.
    """
    global _pool
    if _pool is None:
        _pool = _build_pool()
    return _pool.getconn()


def release_connection(conn):
    """Returns a connection to the pool. Safe to call with None."""
    global _pool
    if _pool is not None and conn is not None:
        _pool.putconn(conn)
