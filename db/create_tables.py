import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from db.database import get_connection, release_connection


def _migrate_schema(cursor):
    """Bring older databases in line with the current schema."""
    cursor.execute(
        """
        ALTER TABLE security_logs
        ADD COLUMN IF NOT EXISTS backend_key VARCHAR(100) NOT NULL DEFAULT 'direct'
        """
    )
    cursor.execute(
        """
        ALTER TABLE rate_limit
        ADD COLUMN IF NOT EXISTS backend_key VARCHAR(100) NOT NULL DEFAULT 'direct'
        """
    )
    cursor.execute(
        "ALTER TABLE rate_limit DROP CONSTRAINT IF EXISTS rate_limit_ip_endpoint_key"
    )
    cursor.execute(
        """
        DO $$ BEGIN
            ALTER TABLE rate_limit
            ADD CONSTRAINT rate_limit_ip_endpoint_backend_key
            UNIQUE (ip, endpoint, backend_key);
        EXCEPTION
            WHEN duplicate_object THEN NULL;
        END $$
        """
    )


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            username   VARCHAR(100) NOT NULL UNIQUE,
            password   VARCHAR(255) NOT NULL,
            created_at TIMESTAMP    NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER      NOT NULL REFERENCES users(id),
            token      TEXT         NOT NULL UNIQUE,
            ip         VARCHAR(45)  NOT NULL,
            created_at TIMESTAMP    NOT NULL,
            expires_at TIMESTAMP    NOT NULL,
            is_active  BOOLEAN      NOT NULL DEFAULT true
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backend_registration (
            id         SERIAL PRIMARY KEY,
            name       VARCHAR(100) NOT NULL,
            target_url VARCHAR(255) NOT NULL,
            api_key    VARCHAR(100) NOT NULL UNIQUE,
            is_active  BOOLEAN      NOT NULL DEFAULT true,
            user_id    INTEGER      NOT NULL REFERENCES users(id),
            UNIQUE (name, user_id)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id          SERIAL PRIMARY KEY,
            ip          VARCHAR(45)  NOT NULL,
            endpoint    VARCHAR(255) NOT NULL,
            method      VARCHAR(10)  NOT NULL,
            attack_type VARCHAR(50)  NOT NULL,
            was_blocked BOOLEAN      NOT NULL,
            backend_key VARCHAR(100) NOT NULL DEFAULT 'direct',
            created_at  TIMESTAMP    NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rate_limit (
            id            SERIAL PRIMARY KEY,
            ip            VARCHAR(45)  NOT NULL,
            endpoint      VARCHAR(255) NOT NULL,
            backend_key   VARCHAR(100) NOT NULL DEFAULT 'direct',
            request_count INTEGER      NOT NULL DEFAULT 1,
            window_start  TIMESTAMP    NOT NULL DEFAULT NOW(),
            is_blocked    BOOLEAN      NOT NULL DEFAULT false,
            UNIQUE (ip, endpoint, backend_key)
        );
    """)

    _migrate_schema(cursor)

    conn.commit()
    cursor.close()
    release_connection(conn)
    print("Tables created successfully.")


if __name__ == "__main__":
    create_tables()
