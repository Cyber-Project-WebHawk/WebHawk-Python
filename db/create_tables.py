from database import get_connection, release_connection


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

    # Fix #4: backend_registration now has an owning user (user_id).
    # Fix #9: backend names are unique per-owner (a user can't register two
    # backends with the same name; two different users may each have a
    # backend with the same name, same as e.g. GitHub repo names per-owner).
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backend_registration (
            id         SERIAL PRIMARY KEY,
            name       VARCHAR(100) NOT NULL,
            target_url VARCHAR(255) NOT NULL,
            api_key    VARCHAR(100) NOT NULL UNIQUE,
            is_active  BOOLEAN      NOT NULL DEFAULT true,
            user_id    INTEGER      REFERENCES users(id)
        );
    """)

    # Idempotent migration for a database created before Fix #4/#9: adds the
    # ownership column and per-owner name-uniqueness constraint if missing.
    cursor.execute("""
        ALTER TABLE backend_registration
        ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id);
    """)
    cursor.execute("""
        DO $$
        BEGIN
            ALTER TABLE backend_registration
            ADD CONSTRAINT backend_registration_user_id_name_key UNIQUE (user_id, name);
        EXCEPTION
            WHEN duplicate_object THEN NULL;
            WHEN duplicate_table THEN NULL;
        END $$;
    """)

    # security_logs now records EVERY scanned request (allowed and blocked),
    # not just blocked ones - this is what makes "total requests scanned"
    # computable for the analytics dashboard. backend_key mirrors
    # rate_limit's scoping: the caller's API key when traffic comes through
    # the proxy, or "direct" for calls straight to /security/scan.
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

    # Idempotent migration for a database created before this dashboard fix.
    cursor.execute("""
        ALTER TABLE security_logs
        ADD COLUMN IF NOT EXISTS backend_key VARCHAR(100) NOT NULL DEFAULT 'direct';
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_security_logs_created_at ON security_logs (created_at);
    """)

    # Fix #6: rate_limit is now scoped by (ip, endpoint, backend_key) instead
    # of just (ip, endpoint), so two unrelated backends sharing a route name
    # and source IP no longer share a single rate-limit counter.
    # backend_key holds the caller's API key when traffic comes through the
    # proxy, or the literal string "direct" for calls made straight to
    # /security/scan with no associated backend.
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

    # Idempotent migration for a database created before Fix #6.
    cursor.execute("""
        ALTER TABLE rate_limit
        ADD COLUMN IF NOT EXISTS backend_key VARCHAR(100) NOT NULL DEFAULT 'direct';
    """)
    cursor.execute("""
        ALTER TABLE rate_limit DROP CONSTRAINT IF EXISTS rate_limit_ip_endpoint_key;
    """)
    cursor.execute("""
        DO $$
        BEGIN
            ALTER TABLE rate_limit
            ADD CONSTRAINT rate_limit_ip_endpoint_backend_key_key UNIQUE (ip, endpoint, backend_key);
        EXCEPTION
            WHEN duplicate_object THEN NULL;
            WHEN duplicate_table THEN NULL;
        END $$;
    """)

    conn.commit()
    cursor.close()
    release_connection(conn)
    print("Tables created successfully.")


if __name__ == "__main__":
    create_tables()
